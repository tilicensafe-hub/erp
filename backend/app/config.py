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
    cora_certificate_base64: str = ""
    cora_private_key_base64: str = ""
    nfe_online_enabled: bool = False
    nfe_sefaz_engine_online: bool = False
    nfe_production: bool = True
    nfe_certificate_pfx_base64: str = ""
    nfe_certificate_password: str = ""
    nfe_issuer_cnpj: str = ""
    nfe_issuer_ie: str = ""
    nfe_issuer_legal_name: str = ""
    nfe_issuer_trade_name: str = ""
    nfe_issuer_address: str = ""
    nfe_issuer_phone: str = ""
    nfe_issuer_email: str = ""
    nfe_issuer_uf: str = "SP"
    nfe_city_code: str = ""
    nfe_tax_regime: str = "1"
    nfe_series: int = 1

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")


settings = Settings()
