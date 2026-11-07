import os
from pathlib import Path
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from starlette.exceptions import HTTPException as StarletteHTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.config import APP_TITLE, APP_SUBTITLE, BASE_DIR
from app.core.ids_service import IDSService
from app.models.database import (
    get_dashboard_stats,
    get_recent_flows,
    get_active_model_version,
    get_model_versions
)

# API Routers
from app.api.traffic import router as traffic_router
from app.api.cti import router as cti_router
from app.api.drift import router as drift_router
from app.api.models_api import router as models_router
from app.api.explain import router as explain_router

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize Core Service on startup
    service = IDSService.get_instance()
    service.initialize()
    yield

app = FastAPI(
    title=APP_TITLE,
    description=APP_SUBTITLE,
    version="1.0.0",
    lifespan=lifespan
)

# Mount Static Assets & Templates
static_dir = Path(__file__).resolve().parent / "static"
templates_dir = Path(__file__).resolve().parent / "templates"

app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
templates = Jinja2Templates(directory=str(templates_dir))

# Include API Routers
app.include_router(traffic_router)
app.include_router(cti_router)
app.include_router(drift_router)
app.include_router(models_router)
app.include_router(explain_router)

# Utility Stats Endpoint
@app.get("/api/stats", tags=["System Stats"])
def fetch_system_stats():
    return get_dashboard_stats()

# Web Page Routes (Jinja2)
@app.get("/", response_class=HTMLResponse)
async def page_home(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="home.html",
        context={
            "active_page": "home"
        }
    )

@app.get("/dashboard", response_class=HTMLResponse)
async def page_dashboard(request: Request):
    stats = get_dashboard_stats()
    recent = get_recent_flows(limit=15)
    active_ver = get_active_model_version()
    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "active_page": "dashboard",
            "stats": stats,
            "recent_flows": recent,
            "active_version": active_ver
        }
    )

@app.get("/live", response_class=HTMLResponse)
async def page_live_monitor(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="live_monitor.html",
        context={
            "active_page": "live"
        }
    )

@app.get("/cti", response_class=HTMLResponse)
async def page_cti_hub(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="cti_hub.html",
        context={
            "active_page": "cti"
        }
    )

@app.get("/drift", response_class=HTMLResponse)
async def page_drift_retraining(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="drift_retraining.html",
        context={
            "active_page": "drift"
        }
    )

@app.get("/explain", response_class=HTMLResponse)
async def page_xai_shap(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="xai_shap.html",
        context={
            "active_page": "explain"
        }
    )

@app.get("/docs-view", response_class=HTMLResponse)
async def page_docs_view(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="docs_view.html",
        context={
            "active_page": "docs"
        }
    )

@app.get("/404", response_class=HTMLResponse)
async def page_404(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="404.html",
        context={
            "active_page": ""
        },
        status_code=404
    )

@app.exception_handler(StarletteHTTPException)
async def custom_http_exception_handler(request: Request, exc: StarletteHTTPException):
    if exc.status_code == 404 and "text/html" in request.headers.get("accept", ""):
        return templates.TemplateResponse(
            request=request,
            name="404.html",
            context={"active_page": ""},
            status_code=404
        )
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
