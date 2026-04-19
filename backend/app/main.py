import os
from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), '.env'))  # Load root .env

import time
import logging
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from backend.app.routes import scan
from backend.app.database import engine, Base

logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)

# Create DB tables synchronously on startup for MVP
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="LinkVeil API",
    description="Backend service for Hybrid Phishing Detection",
    version="1.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# ── Gzip compression (min 500 bytes to avoid compressing tiny responses) ──
app.add_middleware(GZipMiddleware, minimum_size=500)

# ── CORS configuration ──
allowed_origins = os.getenv("ALLOWED_ORIGINS", "http://localhost:5173").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Request-level timing middleware ──
@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    start = time.perf_counter()
    response = await call_next(request)
    elapsed_ms = (time.perf_counter() - start) * 1000
    response.headers["X-Process-Time-Ms"] = f"{elapsed_ms:.1f}"
    if elapsed_ms > 500:
        logger.warning(f"Slow request: {request.method} {request.url.path} took {elapsed_ms:.0f}ms")
    return response

app.include_router(scan.router, prefix="/api/v1")

@app.get("/health")
def health_check():
    return {"status": "ok", "version": "1.1.0"}
