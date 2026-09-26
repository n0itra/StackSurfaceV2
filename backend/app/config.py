from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "StackSurface"
    environment: str = "development"
    database_url: str = "postgresql+psycopg://stacksurface:stacksurface@postgres:5432/stacksurface"
    redis_url: str = "redis://redis:6379/0"
    max_concurrent_scans: int = 1
    nuclei_auto_update: bool = True
    shodan_api_key: str | None = None
    alterx_limit: int = 5000
    command_timeout_seconds: int = 900
    ffuf_timeout_seconds: int = 1800
    data_dir: str = "/tmp/stacksurface"

    model_config = SettingsConfigDict(env_file=".env", env_prefix="", extra="ignore")


settings = Settings()
