import enum
from flask import Flask, jsonify, render_template
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin, login_manager
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from flask_migrate import Migrate
from decouple import config
from flask import request, redirect, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import logout_user
from zxcvbn import zxcvbn

app = Flask(__name__)

db_user = config('DB_USER')
db_pass = config('DB_PASS')
db_port = config('DB_PORT')
db_name = config('DB_NAME')

app.config['SQLALCHEMY_DATABASE_URI'] = f'postgresql://{db_user}:{db_pass}@localhost:{db_port}/{db_name}'
app.secret_key = config('APP_SECRET_KEY')

db = SQLAlchemy(app)
migrate = Migrate(app, db)

login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))




@app.route('/')
def index():
    return render_template('index.html')


@app.route('/home')
def home():
    return render_template('homepage.html')


@app.route('/sale', methods=['GET', 'POST'])
def sale():
    return render_template('sale.html')


@app.route('/purchase', methods=['GET', 'POST'])
def purchase():
    return render_template('purchase.html')


class UserRolesEnum(enum.Enum):
    regular_user = "regular user"
    super_user = "super user"
    admin = "admin"


class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String)
    email = db.Column(db.String, unique=True)
    password = db.Column(db.String)
    role = db.Column(
        db.Enum(UserRolesEnum),
        default=UserRolesEnum.regular_user,
        server_default=UserRolesEnum.regular_user.value,
        nullable=False
    )
    create_on = db.Column(db.DateTime, server_default=func.now())
    updated_on = db.Column(db.DateTime, onupdate=func.now())





@app.route('/search_barcode', methods=['POST'])
def search_barcode():
    barcode = request.json['barcode']
    barcode_result = MedicineBarcode.query.filter(
        (MedicineBarcode.barcode_1 == barcode) | (MedicineBarcode.barcode_2 == barcode)
    ).first()

    if barcode_result:
        medicine = MedicineDetail.query.get(barcode_result.medicine_id)
        return jsonify({'success': True, 'medicine_name': medicine.medicine_name})
    else:
        return jsonify({'success': False, 'message': 'Barcode not found'})


@app.route('/search_medicine_name', methods=['POST'])
def search_medicine_name():
    search_term = request.json['name']
    medicines = MedicineDetail.query.filter(MedicineDetail.medicine_name.ilike(f'%{search_term}%')).all()
    result = [{'medicine_name': medicine.medicine_name} for medicine in medicines]
    return jsonify(result)


def is_protected_route():
    unprotected_routes = ['/', '/login', '/register']
    return request.path not in unprotected_routes


@app.before_request
def protect_all_routes():
    if is_protected_route() and current_user.is_anonymous:
        return login_manager.unauthorized()


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('home'))

        flash('Invalid email or password', 'danger')

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        full_name = request.form['full_name']
        email = request.form['email']
        password = request.form['password']

        password_strength = zxcvbn(password)

        if password_strength['score'] < 3:
            flash('Password is too weak. Please choose a stronger password.', 'danger')
            return render_template('register.html')

        hashed_password = generate_password_hash(password)

        user = User(full_name=full_name, email=email, password=hashed_password)
        db.session.add(user)
        db.session.commit()

        flash('Registration successful, you can now log in', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))












class MedicineDetail(db.Model):
    __tablename__ = 'medicine_detail'
    medicine_id = db.Column(db.Integer, primary_key=True)
    medicine_name_bg = db.Column(db.String)
    group = db.Column(db.String)
    manufacturer = db.Column(db.String)
    sales_measure = db.Column(db.String)
    medicine_name = db.Column(db.String)
    atc_code = db.Column(db.String)
    opiate = db.Column(db.String)
    nhif_code = db.Column(db.String)
    medicine_barcode = db.relationship('MedicineBarcode', backref='medicine')


class MedicineBarcode(db.Model):
    __tablename__ = 'medicine_barcode'
    barcode_id = db.Column(db.Integer, primary_key=True)
    medicine_id = db.Column(db.Integer, db.ForeignKey('medicine_detail.medicine_id'))
    barcode_1 = db.Column(db.String)
    barcode_2 = db.Column(db.String)


class SESPAList(db.Model):
    __tablename__ = 'sespa_list'
    sespa_id = db.Column(db.Integer, primary_key=True)
    medicine_id = db.Column(db.Integer, db.ForeignKey('medicine_detail.medicine_id'))
    drug_id = db.Column(db.String)
    atc_code = db.Column(db.String)
    inn = db.Column(db.String)
    drug_trade_name = db.Column(db.String)
    nhif_code = db.Column(db.String)
    nscrlp_code = db.Column(db.String)
    is_active = db.Column(db.String)
    product_code = db.Column(db.String)
    nscrlp_drug_id = db.Column(db.String)


