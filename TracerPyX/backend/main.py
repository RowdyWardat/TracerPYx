import io
import os
import re
import shutil
import tempfile
import zipfile
import uuid
import time
from pathlib import Path, PurePosixPath

from fastapi import FastAPI, File, HTTPException, UploadFile
from pydantic import BaseModel, Field
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from backend.analyzer import analyze_project
from backend import pr_storage
from ai_agent.chat import ask as ask_agent, make_context as make_agent_context
from integrations.osv import query_package
from reporter_command.json_report import to_jsonable

app = FastAPI(title="TracerPyX API", version="0.1.0")
frontend_origin = os.getenv("TRACERPYX_FRONTEND_ORIGIN", "http://localhost:3000").rstrip("/")
app.add_middleware(CORSMiddleware, allow_origins=[frontend_origin], allow_methods=["*"], allow_headers=["*"], allow_credentials=True)
from backend.github_pr_routes import router as github_pr_router
app.include_router(github_pr_router)

@app.on_event("startup")
def recover_interrupted_pr_jobs():
    pr_storage.mark_orphaned_jobs()
MAX_UPLOAD = 20 * 1024 * 1024
MAX_FILES = 2000
MAX_UNPACKED = 100 * 1024 * 1024
ANALYSIS_STORE: dict[str, dict] = {}
CHAT_HISTORY: dict[str, list[dict]] = {}
CHAT_TIMES: dict[str, list[float]] = {}

class ChatRequest(BaseModel):
    analysis_id: str = Field(min_length=36, max_length=36)
    message: str = Field(min_length=1, max_length=3000)

class ChatClearRequest(BaseModel):
    analysis_id: str = Field(min_length=36, max_length=36)

@app.get("/")
def index():
    return {"service": "TracerPyX API", "status": "ok", "health": "/api/health", "api_docs": "/docs", "dashboard": "http://localhost:3000"}

@app.get("/api/health")
def health():
    return {"status": "ok", "service": "TracerPyX"}

@app.get("/api/agent/status")
def agent_status():
    import os
    return {"configured": bool(os.getenv("OPENAI_API_KEY")), "provider": "OpenAI Responses API"}

@app.post("/api/agent/chat")
async def agent_chat(payload: ChatRequest):
    analysis = ANALYSIS_STORE.get(payload.analysis_id)
    if analysis is None:
        raise HTTPException(404, "Analysis not found or expired. Run the scan again before starting a chat.")
    now = time.monotonic()
    recent = [instant for instant in CHAT_TIMES.get(payload.analysis_id, []) if now - instant < 60]
    if len(recent) >= 10:
        raise HTTPException(429, "Chat rate limit reached. Wait a minute before sending another message.")
    recent.append(now); CHAT_TIMES[payload.analysis_id] = recent
    history = CHAT_HISTORY.setdefault(payload.analysis_id, [])
    prompt = payload.message.strip()
    if not prompt:
        raise HTTPException(422, "Message cannot be blank.")
    answer = await run_in_threadpool(ask_agent, make_agent_context(analysis), history[-12:], prompt)
    history.extend([{"role": "user", "content": prompt}, {"role": "assistant", "content": answer}])
    CHAT_HISTORY[payload.analysis_id] = history[-24:]
    return {"analysis_id": payload.analysis_id, "answer": answer, "references": []}

@app.post("/api/agent/chat/clear")
def clear_agent_chat(payload: ChatClearRequest):
    CHAT_HISTORY.pop(payload.analysis_id, None)
    return {"cleared": True}

def analyze_zip(data: bytes, filename: str) -> dict:
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise HTTPException(400, "Upload must be a valid ZIP archive.") from exc
    infos = archive.infolist()
    if len(infos) > MAX_FILES:
        raise HTTPException(413, "Archive contains too many files.")
    if sum(i.file_size for i in infos) > MAX_UNPACKED:
        raise HTTPException(413, "Expanded archive exceeds 100 MB.")
    root = Path(tempfile.mkdtemp(prefix="tracerpyx_"))
    unpacked = 0
    try:
        for info in infos:
            if info.is_dir():
                continue
            rel = PurePosixPath(info.filename)
            if rel.is_absolute() or ".." in rel.parts:
                raise HTTPException(400, "ZIP contains an unsafe path.")
            if (info.external_attr >> 16) & 0o170000 == 0o120000:
                continue
            target = (root.joinpath(*rel.parts)).resolve()
            if root.resolve() not in target.parents:
                raise HTTPException(400, "ZIP contains an unsafe path.")
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info) as src, target.open("wb") as dst:
                while chunk := src.read(64 * 1024):
                    unpacked += len(chunk)
                    if unpacked > MAX_UNPACKED:
                        raise HTTPException(413, "Expanded archive exceeds 100 MB.")
                    dst.write(chunk)
        recognized = {"requirements.txt", "pyproject.toml", "Pipfile", "poetry.lock", "Pipfile.lock", "uv.lock", "setup.py", "setup.cfg", "expected_results.json"}
        unsupported_file_paths = [info.filename for info in infos if Path(info.filename).suffix.lower() not in {".py", ".txt", ".toml", ".lock", ".cfg"} and Path(info.filename).name not in recognized]
        return analyze_project(root, filename, unsupported_file_paths, query_package_fn=query_package)
    finally:
        shutil.rmtree(root, ignore_errors=True)

@app.post("/api/analyze")
async def analyze(file: UploadFile = File(...)):
    if not file.filename or not file.filename.lower().endswith(".zip"):
        raise HTTPException(400, "Upload a .zip project archive.")
    data = await file.read(MAX_UPLOAD + 1)
    if len(data) > MAX_UPLOAD:
        raise HTTPException(413, "ZIP upload exceeds 20 MB.")
    try:
        result = await run_in_threadpool(analyze_zip, data, file.filename)
        ANALYSIS_STORE[result["analysis_id"]] = result
        if len(ANALYSIS_STORE) > 50:
            ANALYSIS_STORE.pop(next(iter(ANALYSIS_STORE)))
        return JSONResponse(to_jsonable(result))
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(500, f"Analysis failed: {type(exc).__name__}") from exc
