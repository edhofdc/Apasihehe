# PoC Runner & Web Shell

Aplikasi web sederhana untuk menjalankan Proof of Concept (PoC) CVE-2025-55182 dan menangani koneksi reverse shell secara otomatis melalui antarmuka web (browser).

## Fitur

- **Web-based Interface**: Jalankan exploit langsung dari browser.
- **Auto Listener**: Otomatis menjalankan `nc` (Netcat) pada port acak.
- **Web TTY**: Terminal emulator penuh (xterm.js) di browser yang terhubung ke shell target.
- **Multi-Tab**: Dukungan menjalankan banyak sesi eksploitasi secara bersamaan.
- **Session Management**: Pembersihan otomatis proses (`nc` & `python`) saat tab ditutup.

## Instalasi

1. **Clone Repository**
   ```bash
   git clone https://github.com/edhofdc/Apasihehe.git
   cd Apasihehe
   ```

2. **Buat Virtual Environment** (Rekomendasi)
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # MacOS/Linux
   # atau
   # venv\Scripts\activate  # Windows
   ```

3. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

## Penggunaan

1. **Jalankan Server**
   ```bash
   uvicorn app.main:app --host 0.0.0.0 --port 8000
   ```

2. **Buka Browser**
   Akses `http://localhost:8000`

3. **Jalankan Exploit**
   - Masukkan **Target URL** (contoh: `http://target.com:3000`)
   - Klik **RUN PoC**
   - Tunggu koneksi balik. Jika berhasil, terminal akan menjadi interaktif.

## Struktur Project

- `app/main.py`: Backend server (FastAPI) & WebSocket handler.
- `app/session_manager.py`: Logic untuk spawn process `nc` dan `PoC.py`.
- `app/static/index.html`: Frontend UI.
- `PoC.py`: Script exploit utama.

## Disclaimer

Aplikasi ini dibuat untuk tujuan edukasi dan pengujian keamanan yang sah. Penulis tidak bertanggung jawab atas penyalahgunaan alat ini.
