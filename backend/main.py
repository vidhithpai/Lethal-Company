import sys
import os
from pathlib import Path

# Add project root directory to sys.path so 'backend.routers' imports work anywhere
root_dir = Path(__file__).resolve().parent.parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

load_dotenv()  # Load GEMINI_API_KEY from .env


from backend.routers.security import router as security_router
from backend.routers.query import router as query_router
from backend.routers.scan import router as scan_router
from backend.routers.git_router import router as git_router
from backend.routers.report import router as report_router
from backend.routers.graph import router as graph_router
from backend.routers.tdra import router as tdra_router

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
app.include_router(report_router)
app.include_router(graph_router, prefix="/api/graph")
app.include_router(tdra_router, prefix="/api/tdra")


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "VulnGraph"}


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


if __name__ == "__main__":
    import uvicorn
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8002)
    args = parser.parse_args()
    uvicorn.run("backend.main:app", host="127.0.0.1", 
                port=args.port, reload=True)



