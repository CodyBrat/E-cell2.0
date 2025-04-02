from app import app

# This is the WSGI entry point
application = app

# This file is needed for Vercel deployment
if __name__ == "__main__":
    app.run() 