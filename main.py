import uvicorn
from fastapi import FastAPI
from routers import AuthRouter, AppRouter


app = FastAPI(
    title="Documents Exp API",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

app.include_router(AuthRouter)
app.include_router(AppRouter)


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=False
    )