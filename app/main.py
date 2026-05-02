from fastapi import FastAPI

from app.api.routes.rules import router as rules_router

app = FastAPI()

app.include_router(rules_router)


@app.get("/")
def read_root():
    return {"message": "FastAPI in Docker"}