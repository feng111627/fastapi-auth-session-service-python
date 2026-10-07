"""FastAPI 应用入口。"""
from __future__ import annotations

import time

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app import auth
from app.db import init_db
from app.routes import router


def create_app() -> FastAPI:
    app = FastAPI(title="本地认证授权服务", version="0.1.0")
    init_db(seed=True)
    app.include_router(router)

    @app.exception_handler(auth.AuthError)
    def handle_auth_error(request: Request, exc: auth.AuthError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": {"code": exc.code, "message": exc.message}},
        )

    @app.exception_handler(RequestValidationError)
    def handle_validation(request: Request, exc: RequestValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content={"error": {"code": "validation_error", "message": "请求参数不合法"}},
        )

    @app.get("/")
    def health() -> dict:
        return {"status": "ok", "time": int(time.time())}

    return app


app = create_app()
