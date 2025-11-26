#!/usr/bin/env python3
import json, time, glob, sys, os
import serial
from serial import SerialException

BAUD = 115200
READ_TIMEOUT = 1.0
RECONNECT_DELAY = 1.5
PORT_SCAN_GLOBS = ["/dev/ttyACM*", "/dev/ttyUSB*"]

ALLOWED_PINS = {"123456", "654321"}  # TODO: remplace par DB/API

# CRC32 (même polynôme que l'Arduino)
def crc32_update(crc, data):
    crc ^= data
    for _ in range(8):
        crc = (crc >> 1) ^ (0xEDB88320 & (-(crc & 1)))
    return crc

def crc32_pin_seq(pin: str, seq: int) -> int:
    crc = 0xFFFFFFFF
    for ch in pin.encode():
        crc = crc32_update(crc, ch)
    for i in range(4):
        crc = crc32_update(crc, (seq >> (8*i)) & 0xFF)
    return (~crc) & 0xFFFFFFFF

def find_serial_port():
    cands = []
    for patt in PORT_SCAN_GLOBS:
        cands.extend(glob.glob(patt))
    cands = sorted(set(cands))
    return cands[0] if cands else None

def open_serial_or_wait():
    while True:
        port = find_serial_port()
        if not port:
            print("Aucun Arduino détecté (ttyACM*/ttyUSB*). Nouvelle tentative...", flush=True)
            time.sleep(RECONNECT_DELAY); continue
        try:
            print(f"Connexion à {port} ...", flush=True)
            ser = serial.Serial(port, BAUD, timeout=READ_TIMEOUT)
            time.sleep(2.0)
            return ser, port
        except SerialException as e:
            print(f"Erreur d’ouverture sur {port}: {e}. Retry...", flush=True)
            time.sleep(RECONNECT_DELAY)

def safe_write_line(ser: serial.Serial, text: str):
    ser.write((text + "\n").encode()); ser.flush()

def make_result(valid: bool, seq=None):
    msg = {"event": "pin_result", "valid": bool(valid)}
    if seq is not None:
        try: msg["seq"] = int(seq)
        except: pass
    return json.dumps(msg, separators=(",", ":"))

def main_loop():
    ser, current_port = open_serial_or_wait()
    print("En écoute. Ctrl+C pour quitter.", flush=True)
    last_handled_seq = 0

    while True:
        try:
            raw = ser.readline().decode(errors="ignore").strip()
            if not raw:
                continue

            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                print(f"Ligne non-JSON: {raw}", flush=True); continue

            if data.get("event") != "pin_entered":
                print(f"Événement ignoré: {data.get('event')}", flush=True); continue

            pin = str(data.get("pin") or "")
            seq = data.get("seq")
            crc = data.get("crc32")
            try: seq = int(seq)
            except: seq = None

            # Intégrité / dédoublonnage
            if seq is not None:
                calc = crc32_pin_seq(pin, seq)
                if not isinstance(crc, int) and isinstance(crc, str) and crc.isdigit():
                    try: crc = int(crc)
                    except: crc = None
                if crc is None or calc != crc:
                    print(f"[DROP] CRC invalide (recv={crc}, calc={calc}) seq={seq}", flush=True)
                    # ne pas répondre pour forcer le retry Arduino (idempotent)
                    continue
                if seq <= last_handled_seq:
                    print(f"[DUP] Ancien seq={seq} déjà traité. Ignoré.", flush=True)
                    # Option: renvoyer la même décision mémorisée si tu caches les résultats
                    continue

            is_ok = pin in ALLOWED_PINS
            print(f"PIN recu: {pin if pin else '<vide>'} -> {'OK' if is_ok else 'FAIL'}"
                  + (f" | seq={seq}" if seq is not None else ""), flush=True)

            safe_write_line(ser, make_result(is_ok, seq))
            if seq is not None:
                last_handled_seq = seq

        except SerialException as e:
            print(f"[I/O] Perte du port ({current_port}): {e}. Reconnexion...", flush=True)
            try: ser.close()
            except: pass
            time.sleep(RECONNECT_DELAY)
            ser, current_port = open_serial_or_wait()
            print("Repris l’écoute.", flush=True)
        except KeyboardInterrupt:
            print("\nInterruption. Fermeture...", flush=True)
            try: ser.close()
            except: pass
            sys.exit(0)
        except Exception as e:
            print(f"[WARN] Exception inattendue: {e}", flush=True)
            time.sleep(0.05)

if __name__ == "__main__":
    os.environ["PYTHONUNBUFFERED"] = "1"
    main_loop()
