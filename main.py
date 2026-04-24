from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
import os

load_dotenv()  # Load GEMINI_API_KEY from .env

from backend.routers.security import router as security_router
from backend.routers.query import router as query_router
from backend.routers.scan import router as scan_router
from backend.routers.git_router import router as git_router

app = FastAPI(
    title="VulnGraph Backend",
    version="2.0.0",
    description="AST-based security graph analysis with AI-powered query and git blame",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(security_router)
app.include_router(query_router)
app.include_router(scan_router)
app.include_router(git_router)


@app.get("/")
def root():
    return {
        "name": "VulnGraph API",
        "version": "2.0.0",
        "endpoints": [
            "/api/graph",
            "/api/attack-paths",
            "/api/high-risk-paths",
            "/api/cve/scan",
            "/api/query/ask",
            "/api/git/blame",
            "/api/git/timeline",
            "/docs",
        ],
    }
