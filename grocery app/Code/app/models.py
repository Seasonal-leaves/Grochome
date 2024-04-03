from app import app
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

'Creating Database'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///grochome.db'
app.config['SECRET_KEY'] = 'extra,encoding,for,signed,session,cookies,incase,of,cookie,data,tampering'

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    
    name = db.Column(db.String(60), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    cart = db.relationship('Cart', backref='user', lazy=True)
    shopping_lists = db.relationship('ShoppingList', backref='user', lazy=True, cascade="all, delete-orphan")


class Section(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    products = db.relationship('Product', backref='section', lazy=True)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    manufacture_date = db.Column(db.Date, nullable=True)
    expiry_date = db.Column(db.Date, nullable=True)
    rate_per_unit = db.Column(db.Float, nullable=False)
    unit_type = db.Column(db.String(20), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    section_id = db.Column(db.Integer, db.ForeignKey('section.id'), nullable=False)
    cart_items_product = db.relationship('CartItem', backref='product_ref', lazy=True,cascade="all, delete-orphan")
    shopping_lists = db.relationship('ShoppingList', backref='product_ref_shopinglist', lazy=True,cascade="all, delete-orphan")

class Cart(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    items = db.relationship('CartItem', backref='cart', lazy=True)

class CartItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cart_id = db.Column(db.Integer, db.ForeignKey('cart.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('section.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    product = db.relationship('Product', backref='cart_items')

class ShoppingList(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    checkout_date = db.Column(db.DateTime, nullable=True)  # Add a new column for checkout date
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    product_name = db.Column(db.String(100), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('section.id'), nullable=False)
    category_name = db.Column(db.String(100), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    product_rate_per_unit = db.Column(db.Float, nullable=False)
    product = db.relationship('Product', backref='shop_item')




with app.app_context():
    db.create_all()