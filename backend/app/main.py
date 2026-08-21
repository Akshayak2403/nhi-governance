
#NHI Governance API entrypoint.

# App entrypoint - creates tables, sets up CORS, mounts the routers.


from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from . import models
from .database import engine, Base
from .routers import upload, identities, agents

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="NHI Governance API",
    description=(
        "Discovers non-human identities from mock cloud directory + activity "
        "log data, maps them to registered AI agents, and evaluates them "
        "against Least Privilege, Segregation of Duties, and Purpose "
        "Boundary policies."
    ),
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # demo project — tighten to specific origins in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(upload.router)
app.include_router(identities.router)
app.include_router(agents.router)


@app.get("/api/health", tags=["meta"])
def health():
    return {"status": "ok"}
