# app/views/main.py

from flask import Blueprint, render_template, session

main = Blueprint('main', __name__)

@main.route('/')
def home():
    session.clear()
    return render_template('index.html')

@main.route('/about')
def about():
    return render_template('about.html')
