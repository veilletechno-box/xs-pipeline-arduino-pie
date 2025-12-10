#!/usr/bin/env python3
"""
Raspberry Pi serial -> API gateway pour validation PIN.

Ce script :
- lit les messages JSON envoyés par l'Arduino via port série
  attendus: {"event":"pin_entered","pin":"123456","seq":42,"crc32":12345678}
- vérifie CRC + séquence (anti-replay)
- envoie une requête POST sécurisée à l'API:
    headers:
      - x-device-key: <DEVICE_API_KEY>
      - x-request-timestamp: <timestamp_ms>
      - x-request-id: <uuid4>
      - Content-Type: application/json
- traite la réponse { "valid": true/false } et renvoie à l'Arduino:
    {"event":"pin_result","valid":true,"seq":42}

Sécurité côté client:
- taille du body vérifiée (MAX_BODY_BYTES)
- inclusion d'un Request-ID unique par requête
- gestion de 429 + Retry-After, erreurs 5xx avec backoff
- normalisation du time-to-respond côté client (MIN_RESPONSE_MS) pour atténuer
  certaines fuites de timing — la protection principale doit rester côté serveur.

Remplace API_URL et DEVICE_API_KEY par tes valeurs réelles.
"""

from __future__ import annotations
from ai_camera.detect import  detect_frisbee_in_webcam_frame

import glob
import json
import logging
import os
import signal
import sys
import time
import uuid
from typing import Iterable, Optional, Tuple

import requests
import serial
from serial import Serial, SerialException

# ---------------- CONFIG ----------------
BAUD = 115200
READ_TIMEOUT = 1.0
RECONNECT_DELAY = 1.5
PORT_SCAN_GLOBS = ["/dev/ttyACM*", "/dev/ttyUSB*"]

API_URL = "https://hbuflidypffzxqkdhevu.supabase.co/functions/v1/validate-pin"    # <-- REMPLACE PAR TON URL
DEVICE_API_KEY = "4e0332c9ce88c8727a6ec5e402bbfc8e281ab2c17f481bbd69f6b9791fde32a8"  # <-- REMPLACE PAR TA CLEF

LOCKER_ID = "L001"       # identifiant du casier (modifiable)
LOG_LEVEL = logging.INFO

# Sécurité / robustesse client
REQUEST_TIMEOUT = 4.0        # timeout pour la requête HTTP (s)
MAX_BODY_BYTES = 2048        # taille max autorisée du body JSON
MIN_RESPONSE_MS = 200        # délai minimal de réponse (ms) pour normalisation côté client
MAX_RETRIES_API = 2          # retries côté client pour erreurs transitoires (exclut 4xx non retriable)
BACKOFF_BASE = 0.5           # backoff initial en secondes
# ----------------------------------------

# ---------- Logging ----------
logger = logging.getLogger("pin_reader")
logger.setLevel(LOG_LEVEL)
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
logger.addHandler(handler)
# --------------------------------

is_item_available = True

# ---------- CRC helpers (même polynôme qu'Arduino) ----------
def _crc32_update(crc: int, data_byte: int) -> int:
    crc ^= data_byte
    for _ in range(8):
        crc = (crc >> 1) ^ (0xEDB88320 & (-(crc & 1)))
    return crc


def crc32_pin_seq(pin: str, seq: int) -> int:
    crc = 0xFFFFFFFF
    for ch in pin.encode("utf-8"):
        crc = _crc32_update(crc, ch)
    for i in range(4):
        crc = _crc32_update(crc, (seq >> (8 * i)) & 0xFF)
    return (~crc) & 0xFFFFFFFF
# -----------------------------------------------------------


# ---------- Utilities ----------
def find_serial_port(globs: Iterable[str] = PORT_SCAN_GLOBS) -> Optional[str]:
    cands = []
    for patt in globs:
        cands.extend(glob.glob(patt))
    cands = sorted(set(cands))
    return cands[0] if cands else None


def make_result_json(valid: bool, seq: Optional[int] = None) -> bytes:
    msg = {"event": "pin_result", "valid": bool(valid)}
    if seq is not None:
        try:
            msg["seq"] = int(seq)
        except Exception:
            pass
    return (json.dumps(msg, separators=(",", ":")) + "\n").encode("utf-8")
# --------------------------------


# ---------- API client ----------
class PinAPIClient:
    """
    Client sécurisé vers l'API.
    Gère headers requis, taille du body, retries, et normalisation du temps de réponse.
    """

    def __init__(self, url: str, device_key: str, locker_id: str):
        self.url = url
        self.device_key = device_key
        self.locker_id = locker_id
        self.session = requests.Session()
        # Headers statiques partiels (Content-Type et device key ajoutés à chaque requête
        # mais on construit x-request-timestamp/x-request-id à la volée)
        self.base_headers = {
            "Content-Type": "application/json",
            "x-device-key": self.device_key,
            "User-Agent": "pin-rpi-client/1.0",
        }

    def _build_headers(self) -> dict:
        """Construit headers dynamiques pour la requête."""
        ts_ms = int(time.time() * 1000)
        req_id = str(uuid.uuid4())
        h = dict(self.base_headers)
        h["x-request-timestamp"] = str(ts_ms)
        h["x-request-id"] = req_id
        return h

    def validate_pin(self, pin: str) -> Tuple[bool, Optional[int]]:
        """
        Appelle l'API. Retourne (is_valid, http_status) — http_status utile pour debug.
        - Respecte MAX_BODY_BYTES
        - Gère 429 avec Retry-After si présent
        - Retry pour erreurs transitoires (5xx, timeout, connection errors)
        - Normalise le temps de réponse (MIN_RESPONSE_MS)
        """
        payload = {"pin_code": pin, "locker_id": self.locker_id}
        body = json.dumps(payload, separators=(",", ":"))
        body_bytes = body.encode("utf-8")
        if len(body_bytes) > MAX_BODY_BYTES:
            logger.error("[API] Body trop grand (%d bytes)", len(body_bytes))
            return False, None

        attempt = 0
        while attempt <= MAX_RETRIES_API:
            attempt += 1
            headers = self._build_headers()
            start = time.time()
            try:
                r = self.session.post(
                    self.url,
                    data=body_bytes,
                    headers=headers,
                    timeout=REQUEST_TIMEOUT,
                )
                elapsed_ms = int((time.time() - start) * 1000)
                # Normalisation: si trop rapide, on attend le reste pour éviter fuite timing
                if elapsed_ms < MIN_RESPONSE_MS:
                    to_wait = (MIN_RESPONSE_MS - elapsed_ms) / 1000.0
                    logger.debug("[API] Normalisation timing: sleep %.03fs", to_wait)
                    time.sleep(to_wait)

                # Gestion des codes
                if r.status_code == 200:
                    # parse JSON
                    try:
                        data = r.json()
                    except Exception:
                        logger.error("[API] JSON invalide en réponse")
                        return False, r.status_code

                    if "valid" in data:
                        return bool(data["valid"]), r.status_code

                    # fallback structure
                    if "success" in data and isinstance(data.get("data"), dict):
                        if "valid" in data["data"]:
                            return bool(data["data"]["valid"]), r.status_code

                    logger.warning("[API] Réponse 200 mais structure inattendue: %s", data)
                    return False, r.status_code

                elif r.status_code in (401, 403):
                    logger.error("[API] Auth échouée (status=%d). Vérifie DEVICE_API_KEY.", r.status_code)
                    return False, r.status_code

                elif r.status_code == 429:
                    # Respecter Retry-After si fourni
                    ra = r.headers.get("Retry-After")
                    wait = None
                    try:
                        if ra is not None:
                            wait = float(ra)
                        else:
                            wait = BACKOFF_BASE * (2 ** (attempt - 1))
                    except Exception:
                        wait = BACKOFF_BASE * (2 ** (attempt - 1))
                    logger.warning("[API] 429 Rate-limited. Waiting %.2fs (attempt %d/%d)", wait, attempt, MAX_RETRIES_API + 1)
                    time.sleep(wait)
                    continue  # retry if attempts left

                elif 500 <= r.status_code < 600:
                    # erreur serveur -> backoff & retry
                    wait = BACKOFF_BASE * (2 ** (attempt - 1))
                    logger.warning("[API] Erreur serveur %d. Backoff %.2fs (attempt %d/%d)", r.status_code, wait, attempt, MAX_RETRIES_API + 1)
                    time.sleep(wait)
                    continue

                else:
                    logger.error("[API] Requête non attendue: status=%d body=%s", r.status_code, r.text[:200])
                    return False, r.status_code

            except requests.exceptions.RequestException as exc:
                # Timeout / Connexion -> retry avec backoff
                elapsed_ms = int((time.time() - start) * 1000)
                if elapsed_ms < MIN_RESPONSE_MS:
                    to_wait = (MIN_RESPONSE_MS - elapsed_ms) / 1000.0
                    time.sleep(to_wait)
                wait = BACKOFF_BASE * (2 ** (attempt - 1))
                logger.warning("[API] Exception réseau: %s. Backoff %.2fs (attempt %d/%d)", exc, wait, attempt, MAX_RETRIES_API + 1)
                time.sleep(wait)
                continue

        logger.error("[API] Échec après %d tentatives", MAX_RETRIES_API + 1)
        return False, None
# ------------------------------------


# ---------- Pin validation logic (CRC + seq) ----------
class PinValidator:
    def __init__(self):
        self.last_handled_seq: int = -1

    def should_process_seq(self, seq: Optional[int], recv_crc: Optional[int], pin: str) -> Tuple[bool, Optional[str]]:
        if seq is None:
            return True, None

        calc = crc32_pin_seq(pin, seq)

        # coerce
        if recv_crc is not None and isinstance(recv_crc, str) and recv_crc.isdigit():
            try:
                recv_crc = int(recv_crc)
            except Exception:
                return False, "CRC non-intisable"

        if recv_crc is None:
            return False, f"CRC absent (calc={calc})"
        if not isinstance(recv_crc, int):
            return False, "CRC non entier"

        if calc != recv_crc:
            return False, f"CRC invalide (recv={recv_crc}, calc={calc})"

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
        while not self._closing:
            port = find_serial_port(self.port_globs)
            if not port:
                logger.info("Aucun Arduino détecté (ttyACM*/ttyUSB*). Nouvelle tentative...")
                time.sleep(self.reconnect_delay)
                continue

            try:
                logger.info("Connexion à %s ...", port)
                ser = serial.Serial(port, self.baud, timeout=self.timeout)
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
SERIAL_MANAGER: Optional[SerialManager] = None

# ---------- Main loop ----------
def main_loop():
    os.environ.setdefault("PYTHONUNBUFFERED", "1")

    serial_mgr = SerialManager()
    global SERIAL_MANAGER
    SERIAL_MANAGER = serial_mgr
    validator = PinValidator()
    api_client = PinAPIClient(API_URL, DEVICE_API_KEY, LOCKER_ID)

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

            if event == "door_closed":
                logger.info("Door closed event received.")
                on_door_closed(data)
                continue

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

            logger.info("PIN recu: %s | seq=%s - Validation via API...", (pin or "<vide>"), seq)

            is_ok, status = api_client.validate_pin(pin)
            logger.info("API returned: %s (http=%s)", "OK" if is_ok else "FAIL", status)

            # send response to Arduino
            payload = make_result_json(is_ok, seq)
            if not serial_mgr.safe_write(payload):
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

def on_door_closed(payload: dict) -> None:
    """
    Called when the Arduino notifies that the door is closed.

    `payload` is the full JSON dict received from the Arduino.
    You can later use it to access extra fields you might add,
    like timestamps, locker_id, etc.
    """
    logger.info("[DOOR] Door closed event received: %s", payload)
    global is_item_available
    if is_item_available:
        is_item_available = False
        return

    frisbee_in_box = detect_frisbee_in_webcam_frame()

    if not frisbee_in_box:
        on_wrong_item()
    else:
        on_correct_item()

def _send_item_result(is_correct: bool) -> None:
    """
    Envoie au microcontrôleur un message JSON indiquant si l'objet détecté
    est correct ou non.

    Message envoyé (une seule ligne terminée par '\n') :
      {"event":"item_result","correct":true}
    ou:
      {"event":"item_result","correct":false}
    """
    if SERIAL_MANAGER is None:
        logger.error("[ITEM] Impossible d'envoyer le résultat: SERIAL_MANAGER non initialisé")
        return

    msg = {
        "event": "item_result",
        "correct": bool(is_correct),
    }
    payload = (json.dumps(msg, separators=(",", ":")) + "\n").encode("utf-8")

    if not SERIAL_MANAGER.safe_write(payload):
        logger.warning("[ITEM] Echec d'écriture série pour item_result")


def on_wrong_item() -> None:
    """
    Appelé quand la caméra indique que l'objet est incorrect / absent.
    """
    logger.info("[ITEM] Mauvais objet détecté dans le casier")
    _send_item_result(False)


def on_correct_item() -> None:
    """
    Appelé quand la caméra indique que l'objet correct est présent.
    """
    logger.info("[ITEM] Objet correct détecté dans le casier")
    _send_item_result(True)
    global is_item_available
    is_item_available = True



if __name__ == "__main__":
    main_loop()
