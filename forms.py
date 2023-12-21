from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SubmitField, PasswordField
from wtforms.validators import DataRequired, URL, Length, EqualTo, ValidationError

class ProjectForm(FlaskForm):
    image_url = StringField('Image URL', validators=[DataRequired(), URL()])
    name = StringField('Project Name', validators=[DataRequired()])
    description = TextAreaField('Project Description', validators=[DataRequired()])
    github_link = StringField('GitHub Link', validators=[DataRequired(), URL()])
    submit = SubmitField('Add Project')

class RegisterForm(FlaskForm):
    password = PasswordField("Password", validators=[DataRequired()])
    name = StringField("Name", validators=[DataRequired()])
    submit = SubmitField("Sign Me Up!")


# Create a form to login existing users
class LoginForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Let Me In!")