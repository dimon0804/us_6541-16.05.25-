from flask import Flask, request, jsonify, render_template, abort, redirect, url_for, session, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid
import os


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = "c3c763ccfa9c1db2627b0a670424a3a8d442411c5f5a8a2c193de157d0cd19ce"
app.config['UPLOAD_FOLDER'] = 'media'

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

db = SQLAlchemy(app)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    last_name = db.Column(db.String(100), nullable=False)
    first_name = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(50), nullable=False)
    city = db.Column(db.String(100), nullable=False)
    date_of_birth = db.Column(db.Date, nullable=True)
    password_hash = db.Column(db.String(200), nullable=False)
    avatar = db.Column(db.String(200), nullable=True)
    about = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    posts = relationship('Post', back_populates='author')

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.String(500))
    cover = db.Column(db.String(200), nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    author = relationship('User', back_populates='posts')

@app.route('/')
def index():
    posts = Post.query.order_by(Post.date.desc()).all()
    user = User.query.get(session.get("user_id"))
    return render_template('index.html', posts=posts, user=user)

@app.route('/media/<path:filename>')
def media_file1(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/user/<int:user_id>')
def user_profile(user_id):
    user = User.query.get_or_404(user_id)
    posts = Post.query.filter_by(user_id=user_id).order_by(Post.date.desc()).all()
    return render_template('user_profile.html', user=user, posts=posts)

@app.route('/update-security', methods=['POST'])
def update_security():
    user = User.query.get(session.get('user_id'))
    if not user:
        return jsonify({'error': 'Пользователь не найден'}), 403

    old_password = request.form.get('old_password')
    new_password = request.form.get('new_password')
    new_password_confirm = request.form.get('new_password_confirm')
    new_email = request.form.get('email')
    new_phone = request.form.get('phone')

    if not old_password or not check_password_hash(user.password_hash, old_password):
        return jsonify({'error': 'Неверный старый пароль'}), 400

    if new_password or new_password_confirm:
        if new_password != new_password_confirm:
            return jsonify({'error': 'Новые пароли не совпадают'}), 400
        if new_password:
            user.password_hash = generate_password_hash(new_password)

    if new_email and new_email != user.email:
        if User.query.filter(User.email == new_email, User.id != user.id).first():
            return jsonify({'error': 'Этот email уже используется'}), 400
        user.email = new_email

    if new_phone:
        user.phone = new_phone

    db.session.commit()
    return jsonify({'success': 'Данные успешно обновлены'})

@app.route("/upload-avatar", methods=["POST"])
def upload_avatar():
    if 'avatar' not in request.files:
        return jsonify(success=False, error="Нет файла")

    file = request.files['avatar']
    if file.filename == '':
        return jsonify(success=False, error="Файл не выбран")

    user = User.query.get(session.get("user_id"))
    if not user:
        return jsonify(success=False, error="Пользователь не найден"), 403

    filename = f"{user.id}.jpg"
    upload_folder = os.path.join("media", "avatar")
    os.makedirs(upload_folder, exist_ok=True)
    path = os.path.join(upload_folder, filename)
    file.save(path)

    user.avatar = filename
    db.session.commit()

    return jsonify(success=True, new_avatar_url=url_for('media_file1', filename=f"avatar/{filename}"))

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json() or request.form

    last_name = data.get('lastName')
    first_name = data.get('firstName')
    username = data.get('username')
    email = data.get('email')
    phone = data.get('phone')
    city = data.get('city')
    password = data.get('password')

    required_fields = ['lastName', 'firstName', 'username', 'email', 'phone', 'city', 'password']
    missing = [f for f in required_fields if not data.get(f)]
    if missing:
        return jsonify({'error': f'Отсутствуют поля: {", ".join(missing)}'}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'Пользователь с таким логином уже существует.'}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Пользователь с такой почтой уже существует.'}), 400

    hashed_password = generate_password_hash(password)

    new_user = User(
        last_name=last_name.strip(),
        first_name=first_name.strip(),
        username=username.strip(),
        email=email.strip(),
        phone=phone.strip(),
        city=city.strip(),
        password_hash=hashed_password
    )

    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'Регистрация прошла успешно!', 'redirect': url_for('auth')}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json() or request.form
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'Введите логин и пароль'}), 400

    user = User.query.filter_by(username=username).first()

    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({'error': 'Неверный логин или пароль'}), 401

    session['user_id'] = user.id
    session['username'] = user.username
    session['first_name'] = user.first_name
    session['last_name'] = user.last_name

    return jsonify({'message': f'Добро пожаловать, {user.first_name} {user.last_name}!', 'redirect': url_for('index')}), 200

@app.route('/personal_account', methods=['GET', 'POST'])
def personal_account():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('auth'))

    user = User.query.get(user_id)
    if not user:
        session.clear()
        return redirect(url_for('auth'))

    if request.method == 'POST':
        full_name = request.form.get('full_name', '').strip()
        date_of_birth = request.form.get('birthdate')
        city = request.form.get('city', '').strip()
        about = request.form.get('about', '').strip()

        parts = full_name.split(maxsplit=1)
        user.first_name = parts[0]
        user.last_name = parts[1] if len(parts) > 1 else ''
        user.city = city
        user.about = about

        if date_of_birth:
            try:
                user.date_of_birth = datetime.strptime(date_of_birth, '%Y-%m-%d').date()
            except ValueError:
                pass

        db.session.commit()
        return redirect(url_for('personal_account'))

    posts = Post.query.filter_by(user_id=user_id).all()
    return render_template('personal_account.html', user=user, posts=posts)

@app.route('/create_post', methods=['GET', 'POST'])
def create_post():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('auth'))

    if request.method == 'GET':
        return render_template('create_post.html')

    title = request.form.get('title')
    description = request.form.get('description')
    cover_file = request.files.get('cover')

    if not title or not description or not cover_file:
        return "Все поля обязательны", 400

    if cover_file and allowed_file(cover_file.filename):
        ext = cover_file.filename.rsplit('.', 1)[1].lower()
        filename = f"{uuid.uuid4().hex}.{ext}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        cover_file.save(filepath)
    else:
        return "Недопустимый формат файла", 400

    new_post = Post(
        title=title.strip(),
        description=description.strip(),
        cover=filename,
        user_id=user_id
    )
    db.session.add(new_post)
    db.session.commit()

    return redirect(url_for('index'))

@app.route('/media/<filename>')
def media_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/auth')
def auth():
    return render_template('register.html')

@app.route('/post/<int:post_id>')
def post_detail(post_id):
    post = Post.query.get_or_404(post_id)
    return render_template('post.html', post=post)

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
