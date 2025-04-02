from flask import Flask
import sys
import os

# Add parent directory to path so we can import newapp
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import the Flask app
from newapp import app

# Export the app as "app" for Vercel
app = app

# Export the WSGI handler as "handler" for Vercel
handler = app

# This file is used by Vercel to deploy the Flask app
# It simply imports the app from the main file 