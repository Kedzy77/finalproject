from flask import Flask, redirect, url_for, render_template, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Make sure to set a proper secret key

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)  # Initialize Bcrypt

# Initialize Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # Redirect to login page if user is not authenticated


# User model
class User(db.Model, UserMixin):  # UserMixin позволяет использовать функции Flask-Login
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)


# Contact message model
class ContactMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), nullable=False)
    subject = db.Column(db.String(150), nullable=False)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())


# Create database if it does not exist
if not os.path.exists('users.db'):
    with app.app_context():
        db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route("/")
def home():
    context = {"Data": "Some data here to be sent as dict (JSON)"}
    return render_template("index.html", context=context)


@app.route("/blog")
def blog():
    return render_template("blog.html")

@app.route("/faq")
def faq():
    return render_template("faqinfo.html")



@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        name = request.form['name']
        email = request.form['email']
        subject = request.form['subject']
        message = request.form['message']

        # Сохранение сообщения в базе данных
        new_message = ContactMessage(
            name=name,
            email=email,
            subject=subject,
            message=message
        )
        db.session.add(new_message)
        db.session.commit()

        flash("Your message has been sent successfully!", "success")
        return redirect(url_for('home'))  # Перенаправление на главную страницу (index.html)

    return render_template("contact.html")


@app.route("/blog-details")
def blogdetails():
    return render_template("blog-details.html")

@app.route("/quiz")
def quiz():
    return render_template("quizpage.html")

@app.route("/quizpage2")
def quiz2():
    return render_template("quizpage2.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)  # Логиним пользователя
            flash("Login successful!", "success")
            return redirect(url_for('home'))
        else:
            flash("Invalid email or password", "error")
            return redirect(url_for('login'))

    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        full_name = request.form['full_name']
        email = request.form['email']
        password = request.form['password']

        # Check if user exists
        if User.query.filter_by(email=email).first():
            flash("Email already exists", "error")
            return redirect(url_for('register'))

        # Create new user
        new_user = User(
            full_name=full_name,
            email=email,
            password=bcrypt.generate_password_hash(password).decode('utf-8')
        )
        db.session.add(new_user)
        db.session.commit()
        flash("Registration successful! Please login.", "success")
        return redirect(url_for('login'))

    return render_template("register.html")


@app.route("/profile", methods=["GET", "POST"])
@login_required  # Защищенный маршрут
def profile():
    if request.method == "POST":
        new_email = request.form['email']
        new_password = request.form['password']

        # Update user email and password
        current_user.email = new_email
        if new_password:
            current_user.password = bcrypt.generate_password_hash(new_password).decode('utf-8')

        db.session.commit()
        flash("Profile updated successfully!", "success")
        return redirect(url_for('profile'))

    return render_template("profile.html", full_name=current_user.full_name, email=current_user.email)


@app.route("/delete-account", methods=["POST"])
@login_required  # Защищенный маршрут
def delete_account():
    db.session.delete(current_user)  # Удаляем текущего пользователя
    db.session.commit()
    logout_user()  # Выход из системы
    flash("Account deleted successfully.", "info")
    return redirect(url_for('register'))


@app.route("/logout")
@login_required  # Защищенный маршрут
def logout():
    logout_user()  # Выход из системы
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))


if __name__ == "__main__":
    app.run(host='0.0.0.0', debug=True)
