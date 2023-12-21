from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_sqlalchemy import SQLAlchemy
from forms import ProjectForm, RegisterForm, LoginForm
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from functools import wraps
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your_default_secret_key')
# CONNECT TO DB
if os.environ.get("LOCAL") == "True":
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///portfolio.db'
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL")
db = SQLAlchemy(app)
csrf = CSRFProtect(app)
csrf.init_app(app)

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    image_url = db.Column(db.String(150), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    github_link = db.Column(db.String(150), nullable=False)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
with app.app_context():
        db.create_all()
    
# Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.id != 1:
            abort(403)  # Forbid access if not the user with ID 1
        return f(*args, **kwargs)
    return decorated_function


@app.route('/')
def index():
    projects = Project.query.all()
    # Pass the projects to the template
    return render_template('index.html', projects=projects)

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/only_for_me_add_project', methods=['GET', 'POST'])
@login_required
@admin_required
def add_project():
    form = ProjectForm()
    if form.validate_on_submit():
        new_project = Project(
            image_url=form.image_url.data,
            name=form.name.data,
            description=form.description.data,
            github_link=form.github_link.data
        )
        db.session.add(new_project)
        db.session.commit()
        flash('Project added successfully!', 'success')
        return redirect(url_for('index'))
    return render_template('add_project.html', form=form)

@app.route('/private_and_anon_register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256', salt_length=8)
        # Create new_user without an email field
        new_user = User(name=form.name.data, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        flash("Account created successfully!", "success")
        return redirect(url_for('index'))
    return render_template('register.html', form=form)


@app.route('/no_body_else_can_login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(name=form.name.data).first()
        # Use the check_password method of the User model for verifying the password
        if user and user.check_password(form.password.data):
            login_user(user)
            flash("Logged in successfully!", "success")
            return redirect(url_for('index'))
        else:
            flash("Login Unsuccessful. Please check name and password", "danger")
    return render_template('login.html', form=form)


@app.route('/secret_logout')
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/delete_project/<int:project_id>', methods=['POST'])
@login_required
@admin_required
def delete_project(project_id):
    project_to_delete = Project.query.get_or_404(project_id)
    db.session.delete(project_to_delete)
    db.session.commit()
    flash('Project deleted successfully!', 'success')
    return redirect(url_for('index'))

if __name__ == "__main__":
    app.run(debug=False)
