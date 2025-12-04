import uvicorn
from fastapi import FastAPI
from routers import AuthRouter


app = FastAPI(title="Documents Exp API")

app.include_router(AuthRouter)


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="127.0.0.1",
        port=8000,
        reload=True
    )