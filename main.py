from fastapi import FastAPI

from backend.routers.graph import router as graph_router

app = FastAPI(title="VulnGraph Graph Engine")

app.include_router(graph_router)

