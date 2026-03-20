import os


class Config:
    SQLALCHEMY_DATABASE_URI = (
        f"postgresql://{os.getenv('POSTGRES_USER')}:{os.getenv('POSTGRES_PASSWORD')}"
        f"@{os.getenv('DB_HOST', os.getenv('POSTGRES_HOST', '127.0.0.1'))}:{os.getenv('POSTGRES_PORT', '5432')}"
        f"/{os.getenv('POSTGRES_DB', os.getenv('POSTGRES_DBNAME', 'postgres'))}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = os.getenv("SECRET_KEY", "morefixes-dev-key")
    AUTH_USER = os.getenv("AUTH_USER", os.getenv("USER", "swadmin"))
    AUTH_PASSWORD = os.getenv("AUTH_PASSWORD", os.getenv("ENV_PWD", os.getenv("PWD", "change-me")))
    APP_HOST = os.getenv("APP_HOST", "127.0.0.1")
    APP_PORT = int(os.getenv("APP_PORT", "9999"))
