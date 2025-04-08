import os
from flask import Flask, request, render_template, redirect, session, flash, url_for, send_from_directory
import bcrypt
from datetime import datetime
from functools import wraps
from pymongo import MongoClient
from bson.objectid import ObjectId
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Get MongoDB URI from environment variable or use the hardcoded one as fallback
uri = os.environ.get('MONGODB_URI', "mongodb+srv://admin_user_1:newpassword123@ecell.g1eovrh.mongodb.net/?appName=ecell")

app = Flask(__name__, static_folder='static')
app.secret_key = os.environ.get('SECRET_KEY', 'secret_key')  # Better to use environment variable

# MongoDB connection
try:
    client = MongoClient(uri, tlsAllowInvalidCertificates=True)
    # Ping the server to check connection
    client.admin.command('ping')
    print("Connected to MongoDB!")
    db = client['project_db']

    # Collections (equivalent to tables in SQL)
    users = db['users']
    projects = db['projects']
    applications = db['applications']

    # Create indexes for unique fields and relationships
    users.create_index('email', unique=True)
    projects.create_index('user_id')
    applications.create_index([('project_id', 1), ('user_id', 1)])
except Exception as e:
    print(f"Error connecting to MongoDB: {e}")
    # Still initialize these variables to avoid NameError
    db = None
    users = None
    projects = None
    applications = None

# Helper functions for user operations
def create_user(name, email, password, is_admin=False):
    try:
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        user = {
            'name': name,
            'email': email,
            'password': hashed_password,
            'description': None,
            'is_admin': is_admin
        }
        return users.insert_one(user).inserted_id
    except Exception as e:
        print(f"Error creating user: {e}")
        return None

def check_password(user, password):
    try:
        return bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8'))
    except Exception as e:
        print(f"Error checking password: {e}")
        return False

def get_user_by_email(email):
    try:
        return users.find_one({'email': email})
    except Exception as e:
        print(f"Error fetching user by email: {e}")
        return None

def get_user_by_id(user_id):
    try:
        if isinstance(user_id, str):
            user_id = ObjectId(user_id)
        return users.find_one({'_id': user_id})
    except Exception as e:
        print(f"Error fetching user by ID: {e}")
        return None

# Helper functions for project operations
def create_project(title, description, user_id):
    try:
        project = {
            'title': title,
            'description': description,
            'user_id': user_id,
            'published': False,
            'created_at': datetime.utcnow()
        }
        return projects.insert_one(project).inserted_id
    except Exception as e:
        print(f"Error creating project: {e}")
        return None

def get_project_by_id(project_id):
    try:
        if isinstance(project_id, str):
            project_id = ObjectId(project_id)
        return projects.find_one({'_id': project_id})
    except Exception as e:
        print(f"Error fetching project by ID: {e}")
        return None

def get_all_projects():
    try:
        return list(projects.find())
    except Exception as e:
        print(f"Error fetching all projects: {e}")
        return []

def get_published_projects():
    try:
        return list(projects.find({'published': True}))
    except Exception as e:
        print(f"Error fetching published projects: {e}")
        return []

# Helper functions for application operations
def create_application(project_id, user_id, message):
    try:
        application = {
            'project_id': project_id,
            'user_id': user_id,
            'message': message,
            'created_at': datetime.utcnow()
        }
        return applications.insert_one(application).inserted_id
    except Exception as e:
        print(f"Error creating application: {e}")
        return None

def get_applications_by_project(project_id):
    try:
        if isinstance(project_id, str):
            project_id = ObjectId(project_id)
        return list(applications.find({'project_id': project_id}))
    except Exception as e:
        print(f"Error fetching applications by project: {e}")
        return []

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('email'):
            user = get_user_by_email(session['email'])
            if user and user.get('is_admin'):
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
        name = request.form.get('name', '')
        email = request.form.get('email', '')
        password = request.form.get('password', '')

        if not name or not email or not password:
            flash('All fields are required', 'error')
            return render_template('register.html')

        # Check if user already exists
        if get_user_by_email(email):
            flash('Email already exists', 'error')
            return render_template('register.html')

        user_id = create_user(name, email, password)
        if user_id:
            flash('Registration successful! Please login.', 'success')
            return redirect('/login')
        else:
            flash('Error creating user. Please try again.', 'error')
            return render_template('register.html')

    return render_template('register.html')

@app.route('/add_admin', methods=['POST'])
@admin_required
def add_admin():
    if request.method == 'POST':
        name = request.form.get('name', '')
        email = request.form.get('email', '')
        password = request.form.get('password', '')
        
        if not name or not email or not password:
            flash('All fields are required', 'error')
            return redirect('/admin-dashboard')
            
        # Check if user already exists
        if get_user_by_email(email):
            flash('Email already exists', 'error')
            return redirect('/admin-dashboard')
            
        user_id = create_user(name, email, password, is_admin=True)
        if user_id:
            flash('Admin user created successfully!', 'success')
        else:
            flash('Error creating admin user', 'error')
        return redirect('/admin-dashboard')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '')
        password = request.form.get('password', '')

        if not email or not password:
            flash('Email and password are required', 'error')
            return render_template('login.html')

        user = get_user_by_email(email)
        
        if user and check_password(user, password):
            session['email'] = user['email']
            if user.get('is_admin'):
                return redirect('/admin-dashboard')
            return redirect('/dashboard')
        else:
            flash('Invalid email or password', 'error')
            return render_template('login.html')

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if not session.get('email'):
        return redirect('/login')
        
    user = get_user_by_email(session['email'])
    if not user:
        session.pop('email', None)
        return redirect('/login')
        
    has_description = bool(user.get('description'))
    
    # Get user's projects and applications
    user_projects = list(projects.find({'user_id': user['_id']}))
    user_applications = list(applications.find({'user_id': user['_id']}))
    
    return render_template('dashboard.html', 
                         user=user, 
                         has_description=has_description,
                         projects=user_projects,
                         applications=user_applications)

@app.route('/logout')
def logout():
    session.pop('email', None)
    return redirect('/login')

@app.route('/projects', methods=['GET', 'POST'])
def projects_route():
    if not session.get('email'):
        return redirect('/login')

    user = get_user_by_email(session['email'])
    if not user:
        session.pop('email', None)
        return redirect('/login')

    if request.method == 'POST':
        if 'title' in request.form:
            title = request.form.get('title', '')
            description = request.form.get('description', '')
            
            if not title:
                flash('Project title is required', 'error')
            else:
                project_id = create_project(title, description, user['_id'])
                if project_id:
                    flash('Project added successfully!', 'success')
                else:
                    flash('Error adding project', 'error')
                    
        elif 'project_id' in request.form:
            project_id = request.form.get('project_id', '')
            try:
                project = get_project_by_id(ObjectId(project_id))
                if project and str(project['user_id']) == str(user['_id']):
                    projects.update_one(
                        {'_id': ObjectId(project_id)},
                        {'$set': {'published': not project['published']}}
                    )
                    flash('Project publication status updated!', 'success')
                else:
                    flash('You do not have permission to update this project', 'error')
            except Exception as e:
                flash(f'Error updating project: {str(e)}', 'error')
                
        elif 'apply_project_id' in request.form:
            project_id = request.form.get('apply_project_id', '')
            message = request.form.get('application_message', '')
            
            try:
                project_id_obj = ObjectId(project_id)
                project = get_project_by_id(project_id_obj)
                
                if not project:
                    flash('Project not found', 'error')
                elif not project['published']:
                    flash('This project is not open for applications', 'error')
                elif str(project['user_id']) == str(user['_id']):
                    flash('You cannot apply to your own project', 'error')
                else:
                    # Check if already applied
                    existing = applications.find_one({
                        'project_id': project_id_obj,
                        'user_id': user['_id']
                    })
                    
                    if existing:
                        flash('You have already applied to this project', 'error')
                    else:
                        application_id = create_application(project_id_obj, user['_id'], message)
                        if application_id:
                            flash('Application submitted successfully!', 'success')
                        else:
                            flash('Error submitting application', 'error')
            except Exception as e:
                flash(f'Error processing application: {str(e)}', 'error')

    all_projects = get_all_projects()
    
    # Enhance projects with user information
    for project in all_projects:
        project_user = get_user_by_id(project['user_id'])
        if project_user:
            project['user_name'] = project_user['name']
        else:
            project['user_name'] = 'Unknown'
            
    return render_template('projects.html', user=user, projects=all_projects)

@app.route('/public-projects')
def public_projects():
    published_projects = get_published_projects()
    
    # Enhance projects with user information
    for project in published_projects:
        project_user = get_user_by_id(project['user_id'])
        if project_user:
            project['user_name'] = project_user['name']
        else:
            project['user_name'] = 'Unknown'
            
    user = None
    if session.get('email'):
        user = get_user_by_email(session['email'])
            
    return render_template('public_projects.html', projects=published_projects, user=user)

@app.route('/edit-profile', methods=['GET', 'POST'])
def edit_profile():
    if not session.get('email'):
        return redirect('/login')

    user = get_user_by_email(session['email'])
    if not user:
        session.pop('email', None)
        return redirect('/login')

    if request.method == 'POST':
        description = request.form.get('description', '')
        try:
            result = users.update_one(
                {'_id': user['_id']},
                {'$set': {'description': description}}
            )
            if result.modified_count > 0:
                flash('Profile updated successfully!', 'success')
            else:
                flash('No changes were made to your profile', 'info')
        except Exception as e:
            flash(f'Error updating profile: {str(e)}', 'error')
        return redirect('/dashboard')

    return render_template('edit_profile.html', user=user)

@app.route('/admin-dashboard')
@admin_required
def admin_dashboard():
    all_projects = get_all_projects()
    all_users = list(users.find())
    
    # Enhance projects with user information
    for project in all_projects:
        project_user = get_user_by_id(project['user_id'])
        if project_user:
            project['user_name'] = project_user['name']
        else:
            project['user_name'] = 'Unknown'
            
    user = get_user_by_email(session['email']) if session.get('email') else None
    return render_template('admin_dashboard.html', projects=all_projects, users=all_users, user=user)

@app.route('/admin-project/<project_id>', methods=['POST'])
@admin_required
def admin_project(project_id):
    try:
        project_id_obj = ObjectId(project_id)
        project = get_project_by_id(project_id_obj)
        if not project:
            flash('Project not found', 'error')
            return redirect(url_for('admin_dashboard'))
            
        action = request.form.get('action')

        if action == 'publish':
            result = projects.update_one(
                {'_id': project_id_obj},
                {'$set': {'published': True}}
            )
            if result.modified_count > 0:
                flash('Project published successfully!', 'success')
            else:
                flash('No changes were made to the project', 'info')
                
        elif action == 'unpublish':
            result = projects.update_one(
                {'_id': project_id_obj},
                {'$set': {'published': False}}
            )
            if result.modified_count > 0:
                flash('Project unpublished successfully!', 'success')
            else:
                flash('No changes were made to the project', 'info')
                
        elif action == 'delete':
            projects.delete_one({'_id': project_id_obj})
            # Also delete related applications
            applications.delete_many({'project_id': project_id_obj})
            flash('Project deleted successfully!', 'success')
        else:
            flash('Invalid action', 'error')
    except Exception as e:
        flash(f'Error processing project action: {str(e)}', 'error')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/static/<path:path>')
def serve_static(path):
    return send_from_directory('static', path)

@app.errorhandler(404)
def page_not_found(e):
    return render_template('indexq.html'), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('indexq.html'), 500

if __name__ == '__main__':
    app.run(port=5500, debug=True)