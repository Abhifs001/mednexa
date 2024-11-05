# app/views/__init__.py

from flask import Blueprint

# Create blueprints for authentication and main routes
auth = Blueprint('auth', __name__)
main = Blueprint('main', __name__)
