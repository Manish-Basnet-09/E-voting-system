from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .config import settings
from .database import create_tables
from .routers import auth, voter, admin
import uvicorn

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="""
## E-Voting System — Patan Multiple Campus, Tribhuvan University

A secure, transparent, and verifiable digital voting platform.

### Security Stack
- **SHA-256** salted hashing for Student ID (One-ID-One-Vote)
- **RSA** asymmetric encryption for vote privacy
- **Isolation Forest** ML for real-time fraud detection
- **JWT** + **OTP** for three-factor authentication

### Submitted By
- Ashutosh Adhikari (79010020)
- Manish Basnet (79010054)
- Snehal Sigdel (79010119)
    """,
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins.split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routers
app.include_router(auth.router)
app.include_router(voter.router)
app.include_router(admin.router)


@app.on_event("startup")
async def startup_event():
    create_tables()
    print(f"✅ {settings.app_name} v{settings.app_version} started.")
    print("📋 API Docs: http://localhost:8000/docs")


@app.get("/", tags=["Root"])
def root():
    return {
        "system": settings.app_name,
        "version": settings.app_version,
        "status": "operational",
        "institution": "Patan Multiple Campus — Tribhuvan University",
        "security": ["SHA-256", "RSA-2048", "Isolation Forest", "JWT+OTP"],
        "docs": "/docs",
    }


@app.get("/health", tags=["Root"])
def health():
    return {"status": "healthy"}

#  Run the server
if __name__ == "__main__":
    print("Server started! Go to http://127.0.0.1:8000/docs to see the Swagger UI.")
    uvicorn.run(app, host="127.0.0.1", port=8000)