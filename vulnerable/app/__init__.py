import os

from flask import Flask

import config
from . import db


def create_app(overrides=None):
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=config.SECRET_KEY,
        DB_PATH=config.DB_PATH,
        STORAGE_DIR=config.STORAGE_DIR,
        PKI_DIR=config.PKI_DIR,
        MASTER_KEY=config.MASTER_KEY,
        SESSION_COOKIE_HTTPONLY=False,  # VULNERABILITE : cookie lisible par JavaScript
    )
    if overrides:
        app.config.update(overrides)
    for path in (app.config["STORAGE_DIR"], app.config["PKI_DIR"],
                 os.path.dirname(app.config["DB_PATH"])):
        os.makedirs(path, exist_ok=True)
    db.init_app(app)
    from .routes import bp
    app.register_blueprint(bp)
    return app
