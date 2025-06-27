from contextlib import asynccontextmanager
import sys
from pathlib import Path

# Добавляем src/ в PYTHONPATH
sys.path.append(str(Path(__file__).parent.parent))
from alembic import command
from alembic.config import Config
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from sqladmin import Admin

from rarity_api.admin.user_admin import UserAdmin
from rarity_api.common.http_client import HttpClient
from rarity_api.core.database.connector import get_engine_sync
from rarity_api.endpoints.verification_router import router as verification_router
from rarity_api.endpoints.city_router import router as city_router
from rarity_api.endpoints.country_router import router as country_router
from rarity_api.endpoints.item_router import router as item_router
from rarity_api.endpoints.manufacturer_router import router as manufacturer_router
from rarity_api.endpoints.region_router import router as region_router
from rarity_api.endpoints.search_history_router import router as search_history_router
from rarity_api.common.auth.google_auth.router import router as google_auth_router
from rarity_api.common.auth.google_auth.utils.id_provider_certs import IdentityProviderCerts
from rarity_api.common.auth.native_auth.router import router as plain_auth_router
from rarity_api.endpoints.user_router import router as user_router
from rarity_api.endpoints.payment_router import router as payment_router
from rarity_api.settings import settings
from rarity_api.common.auth.yandex_auth.router import router as yandex_router
from starlette.middleware.cors import CORSMiddleware

app = FastAPI(
    title="Rarity API",
    description="API for managing porcelain rarity data",
    version="1.0.0",
    root_path="/api"
)

app.add_middleware(
    CORSMiddleware, 
    allow_origins=["http://localhost", "http://localhost:8081"], 
    allow_credentials=True, 
    allow_methods=["*"], 
    allow_headers=["*"])

app.include_router(google_auth_router)
app.include_router(plain_auth_router)
# Include all routers
app.include_router(country_router)
app.include_router(region_router)
app.include_router(city_router)
app.include_router(manufacturer_router)
app.include_router(item_router)
app.include_router(search_history_router)
app.include_router(yandex_router)
app.include_router(user_router)
app.include_router(payment_router)
app.include_router(verification_router)
# Static files
app.mount("/images", StaticFiles(directory="src/rarity_api/images"), name="images")

admin = Admin(app, get_engine_sync())
admin.add_view(UserAdmin)

@asynccontextmanager
async def lifespan():
    http_client = HttpClient()
    await http_client.init_session()
    await IdentityProviderCerts().renew_certs()
    run_migrations()
    yield
    await http_client.close_session()


def run_migrations():
    alembic_cfg = Config("alembic.ini")
    command.upgrade(alembic_cfg, "head")
