import os
import uuid
from datetime import datetime, timedelta
from flask import Flask, render_template, redirect, url_for, flash, abort, request, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, BooleanField, FileField
from wtforms.validators import DataRequired, Length, Email
from flask_wtf.csrf import CSRFProtect



app = Flask(__name__)
app.config['SECRET_KEY'] = 'ADMIN'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///filehost.db'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['ALLOWED_EXTENSIONS'] = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'zip', 'doc', 'docx'}
app.config['LINK_EXPIRE_HOURS'] = 12
csrf = CSRFProtect(app)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)


def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


class RegistrationForm(FlaskForm):

    username = StringField('Username', validators=[DataRequired(), Length(3, 64)])
    email = StringField('Email', validators=[
        DataRequired(),
        Email(),
        Length(max=120)
    ])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Register')


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Login')


class ProfileForm(FlaskForm):
    full_name = StringField('Full Name', validators=[Length(0, 100)])
    avatar = FileField('Avatar')
    submit = SubmitField('Update Profile')


class UploadFileForm(FlaskForm):
    file = FileField('File', validators=[DataRequired()])
    description = TextAreaField('Description')
    submit = SubmitField('Upload')


class EditFileForm(FlaskForm):
    description = TextAreaField('Description')
    submit = SubmitField('Save Changes')


class CreateLinkForm(FlaskForm):
    submit = SubmitField('Generate Download Link')


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, index=True)
    email = db.Column(db.String(120), unique=True, index=True, nullable=False)
    password_hash = db.Column(db.String(128))
    full_name = db.Column(db.String(100))
    avatar = db.Column(db.String(200))
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    files = db.relationship('File', backref='owner', lazy='dynamic')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_avatar_url(self):
        if self.avatar:
            return url_for('static', filename=f'avatars/{self.avatar}')
        return 'https://www.gravatar.com/avatar/default'


class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    original_name = db.Column(db.String(256))
    storage_name = db.Column(db.String(64), unique=True)
    description = db.Column(db.Text)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    size = db.Column(db.Integer)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    download_links = db.relationship('DownloadLink', backref='file', lazy='dynamic')

    def get_download_url(self):
        return url_for('download_file', file_id=self.id)

    def get_size_mb(self):
        return round(self.size / (1024 * 1024), 2) if self.size else 0


class DownloadLink(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(64), unique=True, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime)
    download_count = db.Column(db.Integer, default=0)
    is_active = db.Column(db.Boolean, default=True)
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'))

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if not self.expires_at:
            self.expires_at = datetime.utcnow() + timedelta(hours=app.config['LINK_EXPIRE_HOURS'])

    def is_expired(self):
        return datetime.utcnow() > self.expires_at

    def update_status(self):
        if self.is_expired():
            self.is_active = False
            return False
        return True

    def get_download_url(self):
        return url_for('download_via_link', token=self.token)

    def deactivate(self):
        self.is_active = False
        db.session.commit()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = RegistrationForm()
    if form.validate_on_submit():
        try:
            # Проверяем уникальность username и email
            if User.query.filter_by(username=form.username.data).first():
                flash('Username already exists')
                return redirect(url_for('register'))

            if User.query.filter_by(email=form.email.data).first():
                flash('Email address already registered')
                return redirect(url_for('register'))

            # Проверяем, является ли это первым пользователем
            is_first_user = User.query.count() == 0

            user = User(
                username=form.username.data,
                email=form.email.data,
                is_admin=is_first_user  # Первый пользователь становится администратором
            )
            user.set_password(form.password.data)
            db.session.add(user)
            db.session.commit()

            if is_first_user:
                flash('Admin account created successfully!')
            else:
                flash('Registration successful! Please log in.')

            return redirect(url_for('login'))


        except IntegrityError as e:
            db.session.rollback()
            flash('An error occurred during registration. Please try again.')
            app.logger.error(f'Database error: {str(e)}')
            return redirect(url_for('register'))

    return render_template('auth/register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember_me.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        flash('Invalid username or password')

    return render_template('auth/login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = ProfileForm()
    if form.validate_on_submit():
        current_user.full_name = form.full_name.data

        if form.avatar.data:
            filename = secure_filename(form.avatar.data.filename)
            unique_filename = f"{uuid.uuid4().hex}_{filename}"
            avatar_path = os.path.join(app.root_path, 'static', 'avatars', unique_filename)
            os.makedirs(os.path.dirname(avatar_path), exist_ok=True)
            form.avatar.data.save(avatar_path)

            if current_user.avatar:
                old_avatar = os.path.join('static', 'avatars', current_user.avatar)
                if os.path.exists(old_avatar):
                    os.remove(old_avatar)

            current_user.avatar = unique_filename

        db.session.commit()
        flash('Your profile has been updated!')
        return redirect(url_for('profile'))
    elif request.method == 'GET':
        form.full_name.data = current_user.full_name

    return render_template('profile.html', form=form)


@app.route('/files')
@login_required
def user_files():
    files = current_user.files.order_by(File.upload_date.desc()).all()
    return render_template('files/files.html', files=files)


@app.route('/files/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    form = UploadFileForm()
    if form.validate_on_submit():
        file = form.file.data
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            unique_filename = f"{uuid.uuid4().hex}_{filename}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            file.save(file_path)

            new_file = File(
                original_name=filename,
                storage_name=unique_filename,
                description=form.description.data,
                size=os.path.getsize(file_path),
                owner=current_user
            )
            db.session.add(new_file)
            db.session.commit()

            flash('File uploaded successfully!')
            return redirect(url_for('user_files'))

    return render_template('files/upload.html', form=form)


@app.route('/files/<int:file_id>', methods=['GET', 'POST'])
@login_required
def file_details(file_id):
    file = File.query.get_or_404(file_id)
    if file.owner != current_user and not current_user.is_admin:
        abort(403)

    form = EditFileForm()
    if form.validate_on_submit():
        file.description = form.description.data
        db.session.commit()
        flash('File description updated.')
        return redirect(url_for('file_details', file_id=file.id))
    elif request.method == 'GET':
        form.description.data = file.description

    links = file.download_links.order_by(DownloadLink.created_at.desc()).all()
    link_form = CreateLinkForm()

    return render_template('files/file_details.html',
                           file=file,
                           form=form,
                           links=links,
                           link_form=link_form)


@app.route('/files/<int:file_id>/download')
@login_required
def download_file(file_id):
    file = File.query.get_or_404(file_id)
    if file.owner != current_user and not current_user.is_admin:
        abort(403)

    return send_from_directory(app.config['UPLOAD_FOLDER'],
                               file.storage_name,
                               as_attachment=True,
                               download_name=file.original_name)


@app.route('/files/<int:file_id>/delete', methods=['POST'])
@login_required
def delete_file(file_id):
    file = File.query.get_or_404(file_id)
    if file.owner != current_user:
        abort(403)

    # Delete file from filesystem
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.storage_name)
    if os.path.exists(file_path):
        os.remove(file_path)

    # Delete from database
    db.session.delete(file)
    db.session.commit()

    flash('File deleted successfully.')
    return redirect(url_for('user_files'))

@app.route('/files/<int:file_id>/links/create', methods=['POST'])
@login_required
def create_download_link(file_id):
    file = File.query.get_or_404(file_id)
    if file.owner != current_user:
        abort(403)

    new_link = DownloadLink(token=uuid.uuid4().hex, file=file)
    db.session.add(new_link)
    db.session.commit()

    # Генерируем полный URL для новой ссылки
    full_url = url_for('download_via_link', token=new_link.token, _external=True)
    flash(f'Создана новая ссылка: {full_url}', 'success')
    return redirect(url_for('file_details', file_id=file.id))


@app.route('/download/<token>')
def download_via_link(token):
    link = DownloadLink.query.filter_by(token=token).first_or_404()

    if not link.is_active or link.is_expired():
        if link.is_active:
            link.is_active = False
            db.session.commit()
        abort(410, description="Link expired or deactivated")

    link.download_count += 1
    db.session.commit()

    return send_from_directory(
        app.config['UPLOAD_FOLDER'],
        link.file.storage_name,
        as_attachment=True,
        download_name=link.file.original_name
    )


@app.route('/admin/users')
@login_required
def admin_users():
    if not current_user.is_admin:
        abort(403)

    users = User.query.order_by(User.created_at.desc()).all()
    return render_template('admin/users.html', users=users)


@app.route('/admin/files')
@login_required
def admin_files():
    if not current_user.is_admin:
        abort(403)

    files = File.query.order_by(File.upload_date.desc()).all()
    return render_template('admin/files.html', files=files)


@app.route('/admin/links')
@login_required
def admin_links():
    if not current_user.is_admin:
        abort(403)

    links = DownloadLink.query.order_by(DownloadLink.created_at.desc()).all()
    return render_template('admin/links.html', links=links)


@app.route('/admin/users/<int:user_id>/toggle_admin', methods=['POST'])
@login_required
def toggle_admin(user_id):
    if not current_user.is_admin:
        abort(403)

    user = User.query.get_or_404(user_id)

    # Запрещаем изменение своего статуса
    if user == current_user:
        flash('You cannot change your own admin status', 'danger')
        return redirect(url_for('admin_users'))

    user.is_admin = not user.is_admin
    db.session.commit()

    action = "granted" if user.is_admin else "revoked"
    flash(f'Admin rights {action} for {user.username}')
    return redirect(url_for('admin_users'))


@app.route('/links/<int:link_id>/delete', methods=['POST'])
@login_required
def delete_link(link_id):
    link = DownloadLink.query.get_or_404(link_id)
    file = link.file

    # Проверка прав: владелец файла или администратор
    if file.owner != current_user and not current_user.is_admin:
        abort(403)

    db.session.delete(link)
    db.session.commit()
    flash('Ссылка удалена', 'success')
    return redirect(url_for('file_details', file_id=file.id))


@app.route('/links/<int:link_id>/deactivate', methods=['POST'])
@login_required
def deactivate_link(link_id):
    link = DownloadLink.query.get_or_404(link_id)
    file = link.file

    if file.owner != current_user and not current_user.is_admin:
        abort(403)

    link.deactivate()
    flash('Ссылка деактивирована', 'success')
    return redirect(url_for('file_details', file_id=file.id))


if __name__ == '__main__':  # Исправлено: должно быть '__main__'
    with app.app_context():
        db.create_all()
    app.run(debug=True)