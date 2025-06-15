# app/__init__.py

import logging
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from app.config import Config
from sqlalchemy import text  # Import the text function

# Initialize extensions
db = SQLAlchemy()
migrate = Migrate()

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    


    # Set up logging
    logging.basicConfig(level=logging.INFO)  # Set logging level to INFO
    logger = logging.getLogger(__name__)

    # Initialize extensions with app
    db.init_app(app)
    migrate.init_app(app, db)

    # Try to connect to the database
    try:
        with app.app_context():
            db.create_all()
            # Use text() for the SQL expression
        logger.info("Database connection established successfully.")
    except Exception as e:
        logger.error("Database connection failed: %s", e)

    # Register blueprints (views)
    from app.views.auth import auth as auth_blueprint
    from app.views.main import main as main_blueprint
    app.register_blueprint(auth_blueprint)
    app.register_blueprint(main_blueprint)

    return app
