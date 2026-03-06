# api/config.py
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    DB_HOST:            str = "localhost"
    DB_PORT:            int = 3306
    DB_NAME:            str = "railway"
    DB_USER:            str = "root"
    DB_PASSWORD:        str = ""
    JWT_SECRET:         str = "changeme"
    JWT_ALGORITHM:      str = "HS256"
    JWT_EXPIRE_MINUTES: int = 60

    class Config:
        env_file = ".env"

settings = Settings()
