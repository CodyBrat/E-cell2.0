from flask import Flask, request, render_template, redirect, session, flash, url_for
from flask_sqlalchemy import SQLAlchemy
import bcrypt
from datetime import datetime
from functools import wraps
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.secret_key = 'secret_key'

# Configure for Vercel deployment
if os.environ.get('VERCEL_REGION') or os.environ.get('VERCEL'):
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    description = db.Column(db.Text)
    is_admin = db.Column(db.Boolean, default=False)

    def __init__(self, email, password, name, is_admin=False):
        self.name = name
        self.email = email
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        self.is_admin = is_admin

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password.encode('utf-8'))

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('projects', lazy=True))
    published = db.Column(db.Boolean, default=False)
    applications = db.relationship('Application', backref='project', lazy=True)

class Application(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref=db.backref('applications', lazy=True))

# Initialize the database
with app.app_context():
    db.create_all()

# For Vercel: create demo data
@app.before_first_request
def create_initial_data():
    if os.environ.get('VERCEL_REGION') or os.environ.get('VERCEL'):
        try:
            # Check if admin exists
            admin = User.query.filter_by(email='admin@example.com').first()
            if not admin:
                admin_user = User(
                    name='Admin User',
                    email='admin@example.com',
                    password='adminpassword',
                    is_admin=True
                )
                db.session.add(admin_user)
                db.session.commit()
                
                # Add a demo project after the admin user is created
                demo_project = Project(
                    title='Demo Project',
                    description='This is a demo project created for testing purposes.',
                    user_id=admin_user.id,
                    published=True
                )
                db.session.add(demo_project)
                db.session.commit()
        except Exception as e:
            print(f"Error creating initial data: {e}")

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('email'):
            user = User.query.filter_by(email=session['email']).first()
            if user and user.is_admin:
                return f(*args, **kwargs)
        flash('You need to be an admin to access this page.', 'error')
        return redirect(url_for('login'))
    return decorated_function

@app.route('/')
def index():
    return render_template('indexq.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        new_user = User(name=name, email=email, password=password)
        db.session.add(new_user)
        db.session.commit()
        return redirect('/login')

    return render_template('register.html')

@app.route('/add_admin', methods=['POST'])
def add_admin():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        is_admin = True

        new_user = User(name=name, email=email, password=password, is_admin=is_admin)
        db.session.add(new_user)
        db.session.commit()
        return redirect('/login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()
        
        if user and user.check_password(password):
            session['email'] = user.email
            if user.is_admin:
                return redirect('/admin-dashboard')
            return redirect('/dashboard')
        else:
            flash('Invalid email or password', 'error')
            return render_template('login.html', error='Invalid user')

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if session.get('email'):
        user = User.query.filter_by(email=session['email']).first()
        has_description = bool(user.description)
        return render_template('dashboard.html', user=user, has_description=has_description)
    else:
        return redirect('/login')

@app.route('/logout')
def logout():
    session.pop('email', None)
    return redirect('/login')

@app.route('/projects', methods=['GET', 'POST'])
def projects():
    if not session.get('email'):
        return redirect('/login')

    user = User.query.filter_by(email=session['email']).first()

    if request.method == 'POST':
        if 'title' in request.form:
            title = request.form['title']
            description = request.form['description']
            new_project = Project(title=title, description=description, user_id=user.id)
            db.session.add(new_project)
            db.session.commit()
            flash('Project added successfully!', 'success')
        elif 'project_id' in request.form:
            project_id = request.form['project_id']
            project = Project.query.get(project_id)
            if project and project.user_id == user.id:
                project.published = not project.published
                db.session.commit()
                flash('Project publication status updated!', 'success')
        elif 'apply_project_id' in request.form:
            project_id = request.form['apply_project_id']
            message = request.form['application_message']
            project = Project.query.get(project_id)
            if project and project.published and project.user_id != user.id:
                new_application = Application(project_id=project_id, user_id=user.id, message=message)
                db.session.add(new_application)
                db.session.commit()
                flash('Application submitted successfully!', 'success')

    projects = Project.query.all()
    return render_template('projects.html', user=user, projects=projects)

@app.route('/public-projects')
def public_projects():
    projects = Project.query.filter_by(published=True).all()
    return render_template('public_projects.html', projects=projects)

@app.route('/edit-profile', methods=['GET', 'POST'])
def edit_profile():
    if not session.get('email'):
        return redirect('/login')

    user = User.query.filter_by(email=session['email']).first()

    if request.method == 'POST':
        user.description = request.form['description']
        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect('/dashboard')

    return render_template('edit_profile.html', user=user)

@app.route('/admin-dashboard')
@admin_required
def admin_dashboard():
    projects = Project.query.all()
    return render_template('admin_dashboard.html', projects=projects)

@app.route('/admin-project/<int:project_id>', methods=['POST'])
@admin_required
def admin_project(project_id):
    project = Project.query.get_or_404(project_id)
    action = request.form.get('action')

    if action == 'publish':
        project.published = True
    elif action == 'unpublish':
        project.published = False
    elif action == 'delete':
        db.session.delete(project)
    
    db.session.commit()
    flash(f'Project {action}ed successfully!', 'success')
    return redirect(url_for('admin_dashboard'))

if __name__ == '__main__':
    app.run(port=5500, debug=True)

