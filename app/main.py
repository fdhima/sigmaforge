from fastapi import FastAPI

from app.api.routes.auth import router as auth_router
from app.api.routes.rules import router as rules_router

app = FastAPI()

app.include_router(auth_router)
app.include_router(rules_router)


@app.get("/")
def read_root():
    return {"message": "FastAPI in Docker"}