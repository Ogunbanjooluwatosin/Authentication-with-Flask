from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key-goes-here'

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy()
db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)


# CREATE TABLE IN DB
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))


with app.app_context():
    db.create_all()


class UserMixinUser(UserMixin):
    def __init__(self, user_id):
        self.id = user_id

    @property
    def is_active(self):
        # Implement your logic to determine if the user is active or not
        return True  # You can modify this logic

    @property
    def is_authenticated(self):
        # Implement your logic to determine if the user is authenticated or not
        return True  # You can modify this logic


@app.route('/')
def home():
    return render_template("index.html")


@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        name = request.form.get("name")
        hashed_password = generate_password_hash(password, method="sha256", salt_length=8)

        new_user = User(
            email=email,
            name=name,
            password=hashed_password,
        )
        db.session.add(new_user)
        db.session.commit()
        flash("You've been registered", "success")
        return render_template("secrets.html", name=request.form.get("name"))

    return render_template("register.html")


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = db.session.query(User).filter_by(email=request.form.get("email")).first()
        if user and check_password_hash(user.password, request.form.get('password')):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('protected_route'))
        flash('Login failed. Please check your username and password.', 'danger')
    return render_template("login.html")



@app.route("/protected")
@login_required
def protected_route():
    return "This route is protected,only authenticated users can access it."


@app.route('/secrets')
def secrets():
    return render_template("secrets.html")


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


@app.route('/download/static/files/<path:filename>', methods=["GET", "POST"])
def download(filename):
    return send_from_directory("static/files", filename)


if __name__ == "__main__":
    app.run(debug=True)
