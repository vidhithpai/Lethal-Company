from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.routers.graph import router as graph_router
from backend.routers.security import router as security_router


app = FastAPI(title="VulnGraph Backend", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(graph_router)
app.include_router(security_router)

