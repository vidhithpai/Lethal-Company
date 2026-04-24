from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.routers.graph import router as graph_router
from backend.routers.query import router as query_router
from backend.routers.patch import router as patch_router


app = FastAPI(title="VulnGraph AI Query Layer", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(graph_router)
app.include_router(query_router)
app.include_router(patch_router)

