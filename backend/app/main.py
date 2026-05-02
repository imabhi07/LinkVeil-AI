import os
import asyncio
import time
import logging
from contextlib import asynccontextmanager
from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), '.env'))  # Load root .env
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.staticfiles import StaticFiles
from backend.app.routes import scan, analytics
from backend.app.database import engine, Base

logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)

# Create DB tables synchronously on startup for MVP
Base.metadata.create_all(bind=engine)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup logic
    from backend.app.services.threat_intel_service import threat_intel_service
    # Start background refresh task and store reference
    app.state.threat_intel_task = asyncio.create_task(threat_intel_service.background_refresh())
    logger.info("Threat Intel background refresh task started.")
    
    yield
    
    # Shutdown logic
    logger.info("Shutting down background tasks...")
    if hasattr(app.state, 'threat_intel_task'):
        app.state.threat_intel_task.cancel()
        try:
            await app.state.threat_intel_task
        except asyncio.CancelledError:
            logger.info("Threat Intel background task cancelled successfully.")
        except Exception as e:
            logger.error(f"Error while cancelling Threat Intel task: {e}")

app = FastAPI(
    title="LinkVeil API",
    description="Backend service for Hybrid Phishing Detection",
    version="1.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
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

app.include_router(scan.router, prefix="/api/v1", tags=["Scanning"])
app.include_router(analytics.router, prefix="/api/v1/analytics", tags=["Analytics"])

# ── Serve screenshots ──
os.makedirs("data/screenshots", exist_ok=True)
app.mount("/data/screenshots", StaticFiles(directory="data/screenshots"), name="screenshots")

@app.get("/health")
def health_check():
    return {"status": "ok", "version": "1.1.0"}
