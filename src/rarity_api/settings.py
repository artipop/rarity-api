import os.path
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import (
    Field,
    BaseModel
)

base_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))

ACCESS_TOKEN_EXPIRE_MINUTES = 1
REFRESH_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7


class NativeAuthJWT(BaseModel):
    private_key_path: Path = Path(os.path.join(base_path, "certs", "jwt-private.pem")) # TODO: refactor later
    public_key_path: Path = Path(os.path.join(base_path, "certs", "jwt-public.pem"))
    algorithm: str = "RS256"
    access_token_expire_minutes: int = ACCESS_TOKEN_EXPIRE_MINUTES
    refresh_token_expire_minutes: int = REFRESH_TOKEN_EXPIRE_MINUTES



class Settings(BaseSettings):
    project_title: str = Field(alias="PROJECT_TITLE")
    api_base_url: str = Field(alias="API_BASE_URL")
    
    fastapi_host: str = Field(alias="FASTAPI_HOST")
    fastapi_port: str = Field(alias="FASTAPI_PORT")

    postgres_user: str = Field(alias="POSTGRES_USER")
    postgres_password: str = Field(alias="POSTGRES_PASSWORD")
    postgres_db: str = Field(alias="POSTGRES_DB")
    postgres_host: str = Field(alias="POSTGRES_HOST")
    postgres_port: str = Field(alias="POSTGRES_PORT")
    
    google_client_id: str = Field(alias="GOOGLE_CLIENT_ID")
    google_client_secret: str = Field(alias="GOOGLE_CLIENT_SECRET")
    google_token_url: str = Field(alias="GOOGLE_TOKEN_URL")
    google_tokeninfo_url: str = Field(alias="GOOGLE_TOKENINFO_URL")
    google_userinfo_url: str = Field(alias="GOOGLE_USERINFO_URL")
    google_authorization_url: str = Field(alias="GOOGLE_AUTHORIZATION_URL")
    google_certs_url: str = Field(alias="GOOGLE_CERTS_URL")
    google_revoke_url: str = Field(alias="GOOGLE_REVOKE_URL")
    certs_issuer: str = Field(alias="CERTS_ISSUER")
    redirect_google_to_uri: str = Field(alias="REDIRECT_GOOGLE_TO_URI")
    post_login_redirect_uri: str = Field(alias="POST_LOGIN_REDIRECT_URI")

    jwt_signing_key: str = Field(alias="JWT_SIGNING_KEY")
    jwt_encoding_algo: str = Field(alias="JWT_ENCODING_ALGORITHM")

    llm_api_url: str = Field(alias="LLM_API_URL")
    llm_api_login: str = Field(alias="LLM_API_LOGIN")
    llm_api_password: str = Field(alias="LLM_API_PASSWORD")

    tochka_api_token: str = Field(alias="TOCHKA_API_TOKEN")
    tochka_customer_code: str = Field(alias="TOCHKA_CUSTOMER_CODE")
    tochka_base_redirect_url: str = Field(alias="TOCHKA_BASE_REDIRECT_URL")

    stripe_api_key: str = Field(alias="STRIPE_API_KEY")
    stripe_monthly_pricing_id: str = Field(alias="STRIPE_MONTHLY_PRICING_ID")
    stripe_yearly_pricing_id: str = Field(alias="STRIPE_YEARLY_PRICING_ID")

    native_auth_jwt: NativeAuthJWT = NativeAuthJWT()

    @property
    def db_url(self) -> str:
        scheme = "postgresql+asyncpg" 
        return (
            f"{scheme}://"
            f"{self.postgres_user}:"
            f"{self.postgres_password}@"
            f"{self.postgres_host}:"
            f"{self.postgres_port}/"
            f"{self.postgres_db}"
        )
    
    model_config = SettingsConfigDict(
        env_file=".env"
    )

settings = Settings()
