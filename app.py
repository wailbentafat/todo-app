from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash
from flask_migrate import Migrate
from flask_login import login_required, current_user, LoginManager, UserMixin
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, BadSignature

app = Flask(__name__, static_url_path='/static')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'wailbentafat@gmail.com'
app.config['MAIL_PASSWORD'] = 'himalaia12'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True

app.config['SECRET_KEY'] = '123376213'

db = SQLAlchemy(app)
migrate = Migrate(app, db)

mail = Mail(app)
serializer = URLSafeTimedSerializer(app.secret_key)

login_manager = LoginManager(app)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(10), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)

class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    title = db.Column(db.String(50))
    complete = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User', backref='todos')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
@login_required
def index():
    todos = Todo.query.filter_by(user_id=current_user.id).all()
    return render_template('index.html', todos=todos)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            return redirect(url_for('index'))
        else:
            return render_template('loginto.html', erreur="Incorrect username or password")
    return render_template('loginto.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        username = request.form['username']
        confirmed, message = check_username(username)
        password = request.form['password']
        confirmed, message = check_password(password)
        if not confirmed:
            flash(message)
            return redirect(url_for('signup'))

        existing_user = User.query.filter_by(username=username).first()

        if existing_user:
            return render_template('registration.html', erreur="Username already exists")
        else:
            password_hash = generate_password_hash(password)
            new_user = User(username=username, password_hash=password_hash, email=email)
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('login'))
    return render_template('registration.html')

@app.route('/add', methods=['POST'])
@login_required
def add_todo():
    title = request.form['title']
    new_todo = Todo(title=title, user_id=current_user.id)
    db.session.add(new_todo)
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit(id):
    todo = Todo.query.get_or_404(id)
    if request.method == 'POST':
        new_title = request.form['new_title']
        todo.title = new_title
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('edit.html', id=id, todo=todo)

@app.route("/delete/<int:id>", methods=['POST'])
@login_required
def delete(id):
    todo = Todo.query.get_or_404(id)
    db.session.delete(todo)
    db.session.commit()
    return redirect(url_for('index'))

@app.route("/logout")
@login_required
def logout():
    return redirect(url_for('login'))

@app.route('/deleteall', methods=['POST'])
@login_required
def deleteall():
    if request.method == 'POST':
        todos = Todo.query.filter_by(user_id=current_user.id).all()
        for todo in todos:
            db.session.delete(todo)
            db.session.commit()
        return redirect(url_for('index'))

@app.route('/reset-password-request', methods=['GET', 'POST'])
def reset_password_request():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user is not None:
            token = serializer.dumps(email, salt='reset-password')
            reset_link = url_for('reset_password', token=token, _external=True)
            send_reset_email(email, reset_link)
            flash('Password reset link sent to your email.')
            return redirect(url_for('login'))
        else:
            flash('Email not found')
            return render_template('reset_password_request.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if request.method == 'POST':
        new_password = request.form['new_password']
        confirmed1, message1 = check_password(new_password)
        if not confirmed1:
            flash(message1)
            return redirect(url_for('reset_password', token=token))

        confirm_password = request.form['confirm_password']

        try:
            email = serializer.loads(token, max_age=3600, salt='reset-password')
            user = User.query.filter_by(email=email).first()
            if user:
                if new_password == confirm_password:
                    user.password_hash = generate_password_hash(new_password)
                    db.session.commit()
                    flash('Your password has been reset successfully.')
                    return redirect(url_for('login'))
                else:
                    flash('Passwords do not match.')
                    return redirect(url_for('reset_password', token=token))
            else:
                flash('User not found.')
                return render_template('reset_password.html', token=token)
        except BadSignature:
            flash('Invalid or expired token.')
            return redirect(url_for('reset_password_request'))

    return render_template('reset_password.html', token=token)

def send_reset_email(email, reset_link):
    msg = Message('Password Reset Request', recipients=[email])
    msg.body = f'''
    To reset your password, visit the following link:
    {reset_link}

    If you did not make this request then simply ignore this email and no changes will be made.
    '''
    mail.send(msg)

def check_password(password):
    if len(password) < 8 or len(password) > 20:
        return False, 'Password must be between 8 and 20 characters.'

    if not any(char.isupper() for char in password):
        return False, 'Password must contain uppercase characters.'

    if not any(char.islower() for char in password):
        return False, 'Password must contain lowercase characters.'

    if not any(char.isdigit() for char in password):
        return False, 'Password must contain at least one digit.'

    special_characters = "~!@#$%^&*()_+=|?/><"
    if not any(char in special_characters for char in password):
        return False, 'Password must contain special characters.'

    return True, ""

def check_username(username):
    if len(username) < 8 or len(username) > 20:
        return False, 'Username must be between 8 and 20 characters.'

    return True, ''

if __name__ == "__main__":
    app.run(debug=True)
