#!/usr/bin/env python3
"""
Refactor du script de lecture série / validation PIN.

Principales améliorations :
- structure en classes (SerialManager, PinValidator)
- logging au lieu de prints
- meilleure gestion des reconnections et des erreurs
- typage et docstrings
"""
from __future__ import annotations

import glob
import json
import logging
import os
import signal
import sys
import time
from typing import Iterable, Optional, Tuple

import serial
from serial import SerialException, Serial

# ---------- Configuration ----------
BAUD = 115200
READ_TIMEOUT = 1.0
RECONNECT_DELAY = 1.5
PORT_SCAN_GLOBS = ["/dev/ttyACM*", "/dev/ttyUSB*"]
ALLOWED_PINS = {"123456", "654321"}  # TODO: charger depuis DB/API si nécessaire
LOG_LEVEL = logging.INFO
# -----------------------------------


# ---------- Logging ----------
logger = logging.getLogger("pin_reader")
logger.setLevel(LOG_LEVEL)
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
logger.addHandler(handler)
# --------------------------------


# ---------- CRC helpers (même polynôme qu'Arduino) ----------
def _crc32_update(crc: int, data_byte: int) -> int:
    """Single-byte CRC-32 update using polynomial 0xEDB88320 (same as Arduino used)."""
    crc ^= data_byte
    for _ in range(8):
        crc = (crc >> 1) ^ (0xEDB88320 & (-(crc & 1)))
    return crc


def crc32_pin_seq(pin: str, seq: int) -> int:
    """
    Compute CRC32 over pin bytes followed by 4 bytes of seq (little-endian),
    starting from 0xFFFFFFFF and then invert - matching Arduino implementation.
    """
    crc = 0xFFFFFFFF
    for ch in pin.encode("utf-8"):
        crc = _crc32_update(crc, ch)
    for i in range(4):
        crc = _crc32_update(crc, (seq >> (8 * i)) & 0xFF)
    return (~crc) & 0xFFFFFFFF
# -----------------------------------------------------------


# ---------- Utilities ----------
def find_serial_port(globs: Iterable[str] = PORT_SCAN_GLOBS) -> Optional[str]:
    """Return first found candidate serial port (sorted), or None."""
    cands = []
    for patt in globs:
        cands.extend(glob.glob(patt))
    cands = sorted(set(cands))
    return cands[0] if cands else None


def make_result_json(valid: bool, seq: Optional[int] = None) -> bytes:
    """Build compact JSON response and return encoded bytes with newline."""
    msg = {"event": "pin_result", "valid": bool(valid)}
    if seq is not None:
        try:
            msg["seq"] = int(seq)
        except Exception:
            pass
    return (json.dumps(msg, separators=(",", ":")) + "\n").encode("utf-8")
# --------------------------------


# ---------- Pin validation logic ----------
class PinValidator:
    def __init__(self, allowed_pins: Iterable[str]):
        self._allowed = set(allowed_pins)
        # last_handled_seq prevents re-processing older sequences.
        # initialize to -1 so seq == 0 is still processed.
        self.last_handled_seq: int = -1

    def is_allowed(self, pin: str) -> bool:
        return pin in self._allowed

    def should_process_seq(self, seq: Optional[int], recv_crc: Optional[int], pin: str) -> Tuple[bool, Optional[str]]:
        """
        Validate CRC and duplicate sequence.
        Return (should_process, reason_if_not).
        """
        if seq is None:
            return True, None

        # compute CRC and compare
        calc = crc32_pin_seq(pin, seq)
        if recv_crc is None:
            return False, f"CRC absent (calc={calc})"
        if not isinstance(recv_crc, int):
            # try to coerce if it's a digit string
            if isinstance(recv_crc, str) and recv_crc.isdigit():
                try:
                    recv_crc = int(recv_crc)
                except Exception:
                    return False, "CRC not intisable"
            else:
                return False, "CRC not int"

        if calc != recv_crc:
            return False, f"CRC invalide (recv={recv_crc}, calc={calc})"

        # deduplication
        if seq <= self.last_handled_seq:
            return False, f"DUP seq={seq} <= last_handled={self.last_handled_seq}"

        return True, None

    def mark_handled(self, seq: Optional[int]) -> None:
        if seq is not None:
            try:
                self.last_handled_seq = int(seq)
            except Exception:
                pass
# ------------------------------------------


# ---------- Serial manager ----------
class SerialManager:
    def __init__(
        self,
        baud: int = BAUD,
        timeout: float = READ_TIMEOUT,
        reconnect_delay: float = RECONNECT_DELAY,
        port_globs: Iterable[str] = PORT_SCAN_GLOBS,
    ):
        self.baud = baud
        self.timeout = timeout
        self.reconnect_delay = reconnect_delay
        self.port_globs = list(port_globs)
        self.ser: Optional[Serial] = None
        self.current_port: Optional[str] = None
        self._closing = False

    def open_or_wait(self) -> Tuple[Serial, str]:
        """Try to open the first found serial port, wait & retry until success."""
        while not self._closing:
            port = find_serial_port(self.port_globs)
            if not port:
                logger.info("Aucun Arduino détecté (ttyACM*/ttyUSB*). Nouvelle tentative...")
                time.sleep(self.reconnect_delay)
                continue

            try:
                logger.info("Connexion à %s ...", port)
                ser = serial.Serial(port, self.baud, timeout=self.timeout)
                # wait a bit for device ready (Arduino auto-reset)
                time.sleep(2.0)
                self.ser = ser
                self.current_port = port
                logger.info("Connecté à %s", port)
                return ser, port
            except SerialException as exc:
                logger.warning("Erreur d'ouverture sur %s: %s. Retry...", port, exc)
                time.sleep(self.reconnect_delay)

        raise RuntimeError("Fermeture demandée; abandon ouverture port")

    def safe_write(self, data: bytes) -> bool:
        """Write bytes and flush; return True on success."""
        if not self.ser:
            logger.debug("safe_write: pas de port ouvert")
            return False
        try:
            self.ser.write(data)
            self.ser.flush()
            return True
        except SerialException as e:
            logger.warning("Erreur écriture série: %s", e)
            return False

    def close(self) -> None:
        self._closing = True
        if self.ser:
            try:
                self.ser.close()
            except Exception:
                pass
            self.ser = None
            logger.info("Port série fermé")
# ----------------------------------


# ---------- Main loop ----------
def main_loop():
    # ensure unbuffered logs for interactive runs
    os.environ.setdefault("PYTHONUNBUFFERED", "1")

    serial_mgr = SerialManager()
    validator = PinValidator(ALLOWED_PINS)

    # handle Ctrl+C gracefully via signal
    def _signal_handler(signum, frame):
        logger.info("Signal d'interruption reçu. Fermeture...")
        serial_mgr.close()
        sys.exit(0)

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    ser, port = serial_mgr.open_or_wait()
    logger.info("En écoute. Ctrl+C pour quitter.")

    while True:
        try:
            if ser is None:
                ser, port = serial_mgr.open_or_wait()

            raw = ser.readline().decode(errors="ignore").strip()
            if not raw:
                continue

            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                logger.debug("Ligne non-JSON: %s", raw)
                continue

            event = data.get("event")
            if event != "pin_entered":
                logger.debug("Événement ignoré: %s", event)
                continue

            pin = str(data.get("pin") or "")
            seq_raw = data.get("seq")
            crc_raw = data.get("crc32")

            # coerce seq to int when possible, else None
            try:
                seq = int(seq_raw) if seq_raw is not None else None
            except Exception:
                seq = None

            should_proc, reason = validator.should_process_seq(seq, crc_raw, pin)
            if not should_proc:
                logger.info("[DROP] %s (pin=%s, seq=%s)", reason, (pin or "<vide>"), seq)
                # Do not respond to force Arduino retry when CRC is bad
                continue

            is_ok = validator.is_allowed(pin)
            logger.info("PIN recu: %s -> %s%s",
                        (pin or "<vide>"),
                        "OK" if is_ok else "FAIL",
                        f" | seq={seq}" if seq is not None else "")

            # send response
            payload = make_result_json(is_ok, seq)
            if not serial_mgr.safe_write(payload):
                # if we failed to write, attempt to reconnect on next loop
                logger.warning("Echec écriture de la réponse; tentative de reconnexion...")
                try:
                    ser.close()
                except Exception:
                    pass
                time.sleep(serial_mgr.reconnect_delay)
                ser, port = serial_mgr.open_or_wait()
                continue

            validator.mark_handled(seq)

        except SerialException as e:
            logger.warning("[I/O] Perte du port (%s): %s. Reconnexion...", serial_mgr.current_port, e)
            try:
                if serial_mgr.ser:
                    serial_mgr.ser.close()
            except Exception:
                pass
            time.sleep(serial_mgr.reconnect_delay)
            ser, port = serial_mgr.open_or_wait()
            continue

        except KeyboardInterrupt:
            logger.info("Interruption clavier. Fermeture...")
            serial_mgr.close()
            sys.exit(0)

        except Exception as e:  # catch-all to avoid crash on unexpected data
            logger.exception("[WARN] Exception inattendue: %s", e)
            time.sleep(0.05)
# ---------------------------------


if __name__ == "__main__":
    main_loop()
