import structlog
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from .core.config import get_settings
from .core.database import init_db
from .api.routes import inventory, audit, alerts

settings = get_settings()
log = structlog.get_logger()


def setup_telemetry(app: FastAPI):
    provider = TracerProvider()
    exporter = OTLPSpanExporter(endpoint=settings.otlp_endpoint, insecure=True)
    provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)
    FastAPIInstrumentor.instrument_app(app)


@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("agentguard_startup", version=settings.app_version)
    await init_db()
    yield
    log.info("agentguard_shutdown")


app = FastAPI(
    title="AgentGuard",
    description="Non-Human Identity security monitor for AI agent stacks — APRA CPS 234 aligned",
    version=settings.app_version,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

setup_telemetry(app)

app.include_router(inventory.router, prefix="/api/v1")
app.include_router(audit.router, prefix="/api/v1")
app.include_router(alerts.router, prefix="/api/v1")


@app.get("/health")
async def health():
    return {"status": "ok", "version": settings.app_version}


@app.get("/")
async def root():
    return {
        "name": "AgentGuard",
        "description": "NHI security monitor for AI agent stacks",
        "docs": "/docs",
        "version": settings.app_version,
    }
