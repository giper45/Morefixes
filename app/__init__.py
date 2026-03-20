from dotenv import load_dotenv
from flask import Flask

from app.api import api_bp
from app.config import Config
from app.extensions import db
from app.web import web_bp


def create_app(config_overrides=None):
    load_dotenv(".env")

    app = Flask(__name__)
    app.config.from_object(Config)
    if config_overrides:
        app.config.update(config_overrides)

    db.init_app(app)

    app.register_blueprint(api_bp, url_prefix="/api")
    app.register_blueprint(web_bp)

    return app
