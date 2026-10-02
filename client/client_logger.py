#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Log Collector Client
====================
Sisi klien dari proyek **Sistem Logging Terdistribusi untuk Deteksi Serangan Jaringan**.

Tugas klien:
  1. Membaca log login (SSH / FTP) dari mesin lokal.
  2. Menyusun pesan log yang ringkas dan konsisten.
  3. Menghitung hash SHA-256 dari ``source|message|timestamp``.
  4. Mengirimkannya ke REST API server melalui ``POST /logs``.

Klien hanya memakai **pustaka standar Python 3** — tidak perlu ``pip install``.
Karena itu program ini cocok dijalankan berkala lewat ``crontab``:

    # Kirim log baru setiap menit
    * * * * * /usr/bin/python3 /opt/sistem-logging/client/client_logger.py >> /var/log/log-client.log 2>&1

Posisi baca terakhir disimpan di *state file* sehingga log yang sama tidak
dikirim dua kali setiap kali cron menjalankan program ini.

Konfigurasi (lewat environment variable, semuanya opsional):

    LOG_SERVER_URL   URL endpoint server      (default: http://localhost:3000/logs)
    CLIENT_SOURCE    Nama identitas klien     (default: client-<hostname>)
    AUTH_LOG         Path log yang dibaca     (default: /var/log/auth.log)
    STATE_FILE       Path state file          (default: <folder script>/.client_state.json)
    REQUEST_TIMEOUT  Timeout HTTP (detik)     (default: 10)
"""

import hashlib
import json
import os
import platform
import re
import socket
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime

# ======================================================
# KONFIGURASI
# ======================================================
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

SERVER_URL = os.environ.get("LOG_SERVER_URL", "http://localhost:3000/logs")
CLIENT_SOURCE = os.environ.get("CLIENT_SOURCE", f"client-{socket.gethostname().lower()}")
AUTH_LOG = os.environ.get("AUTH_LOG", "/var/log/auth.log")
STATE_FILE = os.environ.get("STATE_FILE", os.path.join(SCRIPT_DIR, ".client_state.json"))
REQUEST_TIMEOUT = int(os.environ.get("REQUEST_TIMEOUT", "10"))

# Jumlah event terakhir yang diambil dari Windows Event Log sekali jalan.
WINDOWS_QUERY_COUNT = int(os.environ.get("WINDOWS_QUERY_COUNT", "50"))

DRY_RUN = "--dry-run" in sys.argv


# ======================================================
# UTILITAS
# ======================================================
def now_iso() -> str:
    """Timestamp lokal dalam format ISO 8601 (mikrodetik), sama seperti server."""
    return datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%f")


def compute_hash(source: str, message: str, timestamp: str) -> str:
    """Hitung hash SHA-256 dari ``source|message|timestamp``.

    Urutan dan pemisah ``|`` ini **harus identik** dengan yang dihitung ulang
    oleh ``server.js``; kalau tidak, server akan menolak payload dengan HTTP 403.
    """
    data_string = f"{source}|{message}|{timestamp}"
    return hashlib.sha256(data_string.encode("utf-8")).hexdigest()


def load_state() -> dict:
    """Baca state file; kembalikan dict kosong bila belum ada / rusak."""
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def save_state(state: dict) -> None:
    """Simpan state file secara atomik."""
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(state, fh)
    os.replace(tmp, STATE_FILE)


# ======================================================
# PARSING LOG LINUX (SSH & FTP)
# ======================================================
# Setiap pola menghasilkan (status, protokol, ip).
# Urutan penting: pola "Failed" diperiksa sebelum "Accepted".
LOG_PATTERNS = [
    # sshd — gagal
    (re.compile(r"Failed (?:password|publickey|none) for (?:invalid user )?\S+ from (\S+)"), "Failed", "SSH"),
    (re.compile(r"Invalid user \S+ from (\S+)"), "Failed", "SSH"),
    # sshd — berhasil
    (re.compile(r"Accepted (?:password|publickey) for \S+ from (\S+)"), "Successful", "SSH"),
    # vsftpd — gagal / berhasil
    (re.compile(r'FAIL LOGIN: Client "?([0-9a-fA-F.:]+)'), "Failed", "FTP"),
    (re.compile(r'OK LOGIN: Client "?([0-9a-fA-F.:]+)'), "Successful", "FTP"),
    # proftpd
    (re.compile(r"FTP session opened.*?\[([0-9a-fA-F.:]+)\]"), "Successful", "FTP"),
]


def build_message(status: str, protocol: str, ip: str = None) -> str:
    """Susun pesan log.

    Format ini sengaja dibuat konsisten agar ``mapper.py`` dapat mengenalinya
    hanya dengan mencari kata kunci ``failed`` / ``successful``.

    Contoh keluaran:
        Log: Failed login attempt via SSH from 192.168.107.235
        Log: Successful login attempt on Windows
    """
    if protocol == "Windows":
        return f"Log: {status} login attempt on Windows"
    if ip:
        return f"Log: {status} login attempt via {protocol} from {ip}"
    return f"Log: {status} login attempt via {protocol}"


def read_new_lines(path: str, state: dict) -> list:
    """Baca baris baru sejak offset terakhir, lalu perbarui offset di ``state``.

    Offset disimpan per-path agar satu state file bisa dipakai untuk beberapa
    sumber log sekaligus.
    """
    key = f"offset::{path}"
    start = int(state.get(key, 0))

    try:
        size = os.path.getsize(path)
    except OSError as exc:
        print(f"[WARN] Tidak bisa membaca {path}: {exc}", file=sys.stderr)
        return []

    # File di-rotate (logrotate): ukuran menyusut → baca ulang dari awal.
    if size < start:
        print(f"[INFO] {path} terdeteksi di-rotate, membaca ulang dari awal.", file=sys.stderr)
        start = 0

    if size == start:
        return []  # tidak ada baris baru

    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        fh.seek(start)
        lines = fh.readlines()
        state[key] = fh.tell()

    return lines


def collect_linux(state: dict) -> list:
    """Kumpulkan event login dari log Linux. Mengembalikan list of dict payload."""
    events = []

    for line in read_new_lines(AUTH_LOG, state):
        for pattern, status, protocol in LOG_PATTERNS:
            match = pattern.search(line)
            if not match:
                continue

            ip = match.group(1)
            message = build_message(status, protocol, ip)
            events.append(message)
            break  # satu baris = satu event

    return events


# ======================================================
# PARSING WINDOWS EVENT LOG
# ======================================================
def collect_windows(state: dict) -> list:
    """Kumpulkan event logon Windows (4625 = gagal, 4624 = berhasil).

    Memakai ``wevtutil`` bawaan Windows agar tidak butuh dependensi eksternal.
    Bila ``wevtutil`` tidak tersedia, klien mengembalikan list kosong tanpa
    menggagalkan seluruh proses.
    """
    query = "*[System[(EventID=4625 or EventID=4624)]]"
    cmd = [
        "wevtutil", "qe", "Security",
        f"/q:{query}", "/f:xml", f"/c:{WINDOWS_QUERY_COUNT}", "/rd:true",
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"[WARN] wevtutil tidak bisa dijalankan: {exc}", file=sys.stderr)
        return []

    if result.returncode != 0:
        print(f"[WARN] wevtutil gagal (rc={result.returncode}). "
              f"Jalankan terminal sebagai Administrator.", file=sys.stderr)
        return []

    # Kumpulkan EventID dari output XML. Kita tidak butuh XML parser penuh:
    # cukup ambil setiap blok <Event> lalu cari EventID di dalamnya.
    last_record = int(state.get("windows_last_record", 0))
    highest = last_record
    events = []

    for block in re.findall(r"<Event\b.*?</Event>", result.stdout, re.DOTALL):
        id_match = re.search(r"<EventID>(\d+)</EventID>", block)
        if not id_match:
            continue

        record_match = re.search(r'<EventRecordID>(\d+)</EventRecordID>', block)
        record_id = int(record_match.group(1)) if record_match else 0

        # Lewati event yang sudah pernah dikirim.
        if record_id and record_id <= last_record:
            continue
        highest = max(highest, record_id)

        status = "Failed" if id_match.group(1) == "4625" else "Successful"
        events.append(build_message(status, "Windows"))

    state["windows_last_record"] = highest
    return events


# ======================================================
# PENGIRIMAN KE SERVER
# ======================================================
def build_payload(message: str, timestamp: str) -> dict:
    """Susun payload lengkap beserta hash-nya."""
    return {
        "source": CLIENT_SOURCE,
        "message": message,
        "timestamp": timestamp,
        "hash": compute_hash(CLIENT_SOURCE, message, timestamp),
    }


def send_payload(payload: dict) -> bool:
    """Kirim satu payload ke REST API. Mengembalikan True bila server merespons 201."""
    if DRY_RUN:
        print(f"[DRY-RUN] {json.dumps(payload, ensure_ascii=False)}")
        return True

    request = urllib.request.Request(
        SERVER_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT) as response:
            if response.status == 201:
                print(f"[OK] Terkirim: {payload['message']}")
                return True
            print(f"[WARN] Server merespons HTTP {response.status}", file=sys.stderr)
            return False
    except urllib.error.HTTPError as exc:
        # 403 = hash tidak cocok; 400 = payload tidak lengkap.
        print(f"[ERROR] Ditolak server (HTTP {exc.code}): {payload['message']}", file=sys.stderr)
        return False
    except (urllib.error.URLError, OSError) as exc:
        print(f"[ERROR] Tidak bisa menghubungi server: {exc}", file=sys.stderr)
        return False


# ======================================================
# MAIN
# ======================================================
def main() -> int:
    system = platform.system()
    state = load_state()

    print(f"[{now_iso()}] Log Collector Client — source={CLIENT_SOURCE} os={system}")

    if system == "Linux":
        new_messages = collect_linux(state)
    elif system == "Windows":
        new_messages = collect_windows(state)
    else:
        print(f"[WARN] Platform '{system}' belum didukung.", file=sys.stderr)
        new_messages = []

    # ── Store-and-forward sederhana ──────────────────────
    # Event baru digabung dengan sisa antrean yang belum berhasil terkirim.
    # Timestamp dibuat sekali saat event ditemukan, sehingga retry tidak
    # mengubah hash maupun waktu kejadian aslinya.
    pending = state.get("pending", [])
    pending.extend({"message": msg, "timestamp": now_iso()} for msg in new_messages)

    if not pending:
        print("Tidak ada event login baru.")
        return 0

    sent = 0
    remaining = []
    for item in pending:
        if send_payload(build_payload(item["message"], item["timestamp"])):
            sent += 1
        else:
            remaining.append(item)

    # Mode dry-run bersifat non-destruktif: posisi baca tidak dimajukan dan
    # antrean tidak diubah, supaya event yang sama masih bisa dikirim nanti.
    if DRY_RUN:
        print(f"Dry-run: {len(pending)} event siap kirim (state tidak diubah).")
        return 0

    state["pending"] = remaining
    save_state(state)

    if remaining:
        print(f"Selesai: {sent}/{len(pending)} terkirim, "
              f"{len(remaining)} disimpan di antrean untuk dicoba lagi.")
        return 1

    print(f"Selesai: {sent}/{len(pending)} log terkirim.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
