from newapp import app, init_db

# Initialize the database when running on Vercel
init_db()

# This file is used by Vercel to deploy the Flask app
# It simply imports the app from the main file 