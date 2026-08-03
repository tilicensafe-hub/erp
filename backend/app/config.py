from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    database_url: str
    api_token: str
    app_env: str = "development"
    cora_enabled: bool = False
    cora_production: bool = True
    cora_client_id: str = ""
    cora_certificate_path: str = ""
    cora_private_key_path: str = ""
    cora_certificate_pem: str = ""
    cora_private_key_pem: str = ""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")


settings = Settings()
