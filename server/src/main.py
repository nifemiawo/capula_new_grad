"""Main application entry point."""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from sqlmodel import SQLModel

from server.src.db import engine
from server.src.routes.register import router as register_router
from server.src.routes.store import router as store_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    SQLModel.metadata.create_all(engine)
    yield


app = FastAPI(lifespan=lifespan)

app.include_router(register_router)
app.include_router(store_router)