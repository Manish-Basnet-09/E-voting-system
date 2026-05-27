from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import uvicorn

# Importing your project modules
from .config import settings
from .database import create_tables
from .routers.auth import router as auth_router
from .routers.voter import router as voter_router
from .routers.admin import router as admin_router

# 1. Lifespan context manager
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Run database initialization
    await create_tables()
    print(f"✅ {settings.app_name} v{settings.app_version} started.")
    yield
    # Shutdown logic
    print("🛑 Server shutting down.")

# 2. FastAPI Application Instance
app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="""
## E-Voting System — Patan Multiple Campus, Tribhuvan University

A secure, transparent, and verifiable digital voting platform.
    """,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# 3. CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins.split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 4. Include Routers
app.include_router(auth_router, tags=["Authentication"])
app.include_router(voter_router, tags=["Voter"])
app.include_router(admin_router, tags=["Admin"])

@app.get("/", tags=["Root"])
async def root():
    return {
        "status": "operational", 
        "institution": "Patan Multiple Campus",
        "docs": "http://127.0.0.1:8000/docs"
    }

# 5. Execution Block
if __name__ == "__main__":
    # We use "app.main:app" because the file is located at backend/app/main.py
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)