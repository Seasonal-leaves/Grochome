from app import app
from flask import render_template, flash, redirect, url_for, request
from flask_login import login_user, logout_user, login_required, current_user, LoginManager, UserMixin
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, DateField, SelectField, IntegerField, FloatField
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError, Length
from app.models import User, Product, db, Section, Cart, CartItem, ShoppingList
from flask_bcrypt import Bcrypt

bcrypt = Bcrypt()
login = LoginManager(app)
login.login_view = 'login'
login.init_app(app)
class User(db.Model, UserMixin):
    def __init__(self, name,email,password, is_admin=False):
        # self.id = id
        self.name = name
        self.email = email
        self.password = password
        self.is_admin = is_admin
# Forms
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(max = 60)] )
    email = StringField('Email', validators=[DataRequired(), Length(max = 120)] )
    password = PasswordField('Password', validators=[DataRequired(), Length(max = 40)]) # here max length is set less than the one for database as after the password will be hashed when it is submitted and it's size may increase 
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_email(self, email):
        user_mail = User.query.filter_by(email=email.data).first()
        if user_mail:
            raise ValidationError('The same email ID exists in database. Forgot password?you can reach out to admins. If not choose a different mailID!!')


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Log In')

class AdminLoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Log In')
class CreateCategoryForm(FlaskForm):
    name = StringField('Category Name', validators=[DataRequired()])

class CreateProductForm(FlaskForm):
    name = StringField('Product Name', validators=[DataRequired()])
    manufacture_date = DateField('Manufacture Date', format='%Y-%m-%d', validators=[DataRequired()])
    expiry_date = DateField('Expiry Date', format='%Y-%m-%d', validators=[DataRequired()])
    unit_type = SelectField('Rate per Unit', choices=[('Rs/kg', 'Rs/kg'), ('Rs/litre', 'Rs/litre'), ('Rs/dozen', 'Rs/dozen'), ('Rs/g', 'Rs/g'),('Rs/unit', 'Rs/unit')], validators=[DataRequired()])
    rate_per_unit = FloatField('Rate per Unit', validators=[DataRequired()])
    quantity = IntegerField('Quantity', validators=[DataRequired()])


class EditProductForm(FlaskForm):
    name = StringField('Product Name')
    manufacture_date = DateField('Manufacture Date')
    expiry_date = DateField('Expiry Date')
    unit_type = SelectField('Rate per Unit', choices=[('Rs/kg', 'Rs/kg'), ('Rs/litre', 'Rs/litre'), ('Rs/dozen', 'Rs/dozen'), ('Rs/g', 'Rs/g'),('Rs/unit', 'Rs/unit')])
    rate_per_unit = FloatField('Rate per Unit')
    quantity = IntegerField('Quantity')

class EditCategoryForm(FlaskForm):
    name = StringField('Product Name')
    
# class ConfirmDeleteProductForm(FlaskForm):
#     name = StringField('Product Name')
#     manufacture_date = DateField('Manufacture Date')
#     expiry_date = DateField('Expiry Date')
#     unit_type = SelectField('Rate per Unit', choices=[('Rs/kg', 'Rs/kg'), ('Rs/litre', 'Rs/litre'), ('Rs/dozen', 'Rs/dozen'), ('Rs/g', 'Rs/g'),('Rs/unit', 'Rs/unit')])
#     rate_per_unit = FloatField('Rate per Unit')
#     quantity = IntegerField('Quantity')

@login.user_loader
def load_user(user_id):
    # return the user object for the user with the given user_id
    user= User.query.get(int(user_id))
    return user
    

@app.route('/')
def home():
        categories = Section.query.all()
        return render_template('home.html', categories=categories)
        
   # return "hello flask"
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    form = RegistrationForm()
    if form.validate_on_submit():
        # check if the username is already registered or the username is already taken
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None:
            flash('User already registered !!')
            return redirect(url_for('login'))

        # Create a new user object and set their password
        # hashed_password = generate_password_hash(form.password.data)
        hashed_password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        # new_user = User()
        # new_user.email = form.email.data
        # new_user.name = form.username.data
        # new_user.password = hashed_password
        new_user = User(name = form.username.data,email=form.email.data,  password=hashed_password)
        
        
        
        
        # Add the user object to the database and commit the changes
        db.session.add(new_user)
        db.session.commit()
        
        flash('Successfully Registered !!')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        
        if user and bcrypt.check_password_hash(user.password, request.form['password']):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Login failed. Please check your credentials.', 'danger')
    
    return render_template('login.html', form=form)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('home'))

@app.route('/adminlogin', methods=['GET', 'POST'])
def adminlogin():
    if current_user.is_authenticated :
            if current_user.is_admin:
                return redirect(url_for('admin_dashboard'))
            else:
                flash('You are not an admin.', 'danger')
                return redirect(url_for('home'))
    form = AdminLoginForm()
    # if request.method == 'POST':
    if form.validate_on_submit():  # Using Flask-WTF for form validation.
            email = request.form['email']
            password = request.form['password']
            user = User.query.filter_by(email=email).first()
            
            if user and bcrypt.check_password_hash(user.password, request.form['password']) and user.is_admin:
                login_user(user)
                flash('Login successful!', 'success')
                return redirect(url_for('admin_dashboard'))
            else:
                flash('Login failed. Please check your credentials.', 'danger')
    
    return render_template('admin login.html', form=form)

@app.route('/admin_dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    # categories = Category.query.all()
    if current_user.is_authenticated :
            if current_user.is_admin:
                categories = Section.query.all()
                return render_template('admin dashboard.html', categories=categories)
    return redirect(url_for('home'))

from sqlalchemy import func
@app.route('/create_categories', methods=['GET', 'POST'])
def create_category():
    if current_user.is_authenticated :
            if current_user.is_admin:
                form = CreateCategoryForm()

                if form.validate_on_submit():
                    category_name = form.name.data.strip()
                    name_lower = category_name.lower()
                    # Check if the category name already exists
                    existing_category = Section.query.filter(func.lower(Section.name) == name_lower).first()   #query.filter_by(name=category_name).first()
                    if existing_category:
                        flash('Category already exists.', 'danger')
                    else:
                        # Create a new category and add it to the database
                        new_category = Section(name=category_name)
                        db.session.add(new_category)
                        db.session.commit()
                        flash('Category created successfully!', 'success')
                        return redirect(url_for('admin_dashboard'))

                return render_template('create categories.html', form=form)

@app.route('/create_product/<int:id>', methods=['POST'])
def create_product(id):
    if current_user.is_authenticated :
            if current_user.is_admin:
    # Check if the category with the given category_id exists
                category = Section.query.get(id)

                if category:
                    form = CreateProductForm()

                    if form.validate_on_submit():
                        product_name = form.name.data
                        manufacture_date = form.manufacture_date.data
                        expiry_date = form.expiry_date.data
                        unit_type = form.unit_type.data
                        rate_per_unit = form.rate_per_unit.data
                        quantity = form.quantity.data

                        # Create a new product and associate it with the section
                        new_product = Product(
                            name=product_name,
                            manufacture_date=manufacture_date,
                            expiry_date=expiry_date,
                            unit_type = unit_type,
                            rate_per_unit=rate_per_unit,
                            quantity=quantity,
                            section=category  # Associate the product with the section
                        )

                        db.session.add(new_product)
                        db.session.commit()
                        return redirect(url_for('admin_dashboard'))
                    flash('Product created successfully in category: {}'.format(category.name), 'success')
                    return render_template('create product.html', form=form, section=category)
                else:
                    flash('Section not found.', 'danger')
                    return redirect(url_for('create_category'))
    
@app.route('/edit_product/<int:product_id>', methods=['GET', 'POST'])
def edit_product(product_id):
    if current_user.is_authenticated :
            if current_user.is_admin:
                product = Product.query.get(product_id)

                if product:
                    form = EditProductForm(obj=product)  # Populate form with existing product data

                    if form.validate_on_submit():
                        # Update product details based on the form data
                        form.populate_obj(product)
                        db.session.commit()

                        flash('Product updated successfully!', 'success')
                        return redirect(url_for('admin_dashboard'))

                    return render_template('edit products.html', form=form, product=product)
                else:
                    flash('Product not found.', 'danger')
                    return redirect(url_for('admin_dashboard'))

@app.route('/confirm_delete_product/<int:product_id>', methods=['GET', 'POST'])
def confirm_delete_product(product_id):
    if current_user.is_authenticated :
            if current_user.is_admin:
                product = Product.query.get(product_id)

                if product:
                    return render_template('confirm delete product.html', product=product)
                else:
                    flash('Product not found.', 'danger')

                return redirect(url_for('admin_dashboard'))

@app.route('/delete_product/<int:product_id>', methods=['POST'])
def delete_product(product_id):
    if current_user.is_authenticated :
            if current_user.is_admin:
                product = Product.query.get(product_id)

                if product:
                    db.session.delete(product)
                    db.session.commit()
                    flash('Product deleted successfully!', 'success')
                else:
                    flash('Product not found.', 'danger')

                return redirect(url_for('admin_dashboard'))

@app.route('/edit_category/<int:category_id>', methods=['GET', 'POST'])
def edit_category(category_id):
    if current_user.is_authenticated :
            if current_user.is_admin:
                category = Section.query.get(category_id)

                if category:
                    form = EditCategoryForm(obj=category)  # Populate form with existing product data

                    if form.validate_on_submit():
                        # Update product details based on the form data
                        form.populate_obj(category)
                        db.session.commit()

                        flash('Category updated successfully!', 'success')
                        return redirect(url_for('admin_dashboard'))

                    return render_template('edit category.html', form=form, category=category)

@app.route('/confirm_delete_category/<int:category_id>', methods=['GET', 'POST'])
def confirm_delete_category(category_id):
    if current_user.is_authenticated :
            if current_user.is_admin:
                category = Section.query.get(category_id)

                if category:
                    return render_template('confirm delete category.html', category=category)
                else:
                    flash('Product not found.', 'danger')

                return redirect(url_for('admin_dashboard'))

@app.route('/delete_category/<int:category_id>', methods=['POST'])
def delete_category(category_id):
    if current_user.is_authenticated :
            if current_user.is_admin:
                category = Section.query.get(category_id)

                if category:
                    for product in category.products:
                        db.session.delete(product)
                    db.session.delete(category)
                    db.session.commit()
                    flash('category deleted successfully!', 'success')
                else:
                    flash('category not found.', 'danger')

                return redirect(url_for('admin_dashboard'))


from datetime import datetime
@app.route('/search_home', methods=['POST'])
def search_home():
    categories1 = Section.query.all()
    products1 = Product.query.all()
    search_type = request.form.get('search_type')
    search_query = request.form.get('search_query')
    
    categories = []
    products = []

    if search_type and search_query:
        if search_type == 'category':
            categories = Section.query.filter(Section.name.ilike(f'%{search_query}%')).all()
        elif search_type == 'product':
            products = Product.query.filter(Product.name.ilike(f'%{search_query}%')).all()

        elif search_type == 'manufacture_date_after':
            try:
                search_date = datetime.strptime(search_query, '%Y-%m-%d')
                products = Product.query.filter(Product.manufacture_date >= search_date).all()
            except ValueError:
                flash('Invalid date format for Manufacture Date After.', 'danger')
        elif search_type == 'manufacture_date_before':
            try:
                search_date = datetime.strptime(search_query, '%Y-%m-%d')
                products  = Product.query.filter(Product.manufacture_date <= search_date).all()
            except ValueError:
                flash('Invalid date format for Manufacture Date Before.', 'danger')
        elif search_type == 'expiry_date_after':
            try:
                search_date = datetime.strptime(search_query, '%Y-%m-%d')
                products  = Product.query.filter(Product.expiry_date >= search_date).all()
            except ValueError:
                flash('Invalid date format for Expiry Date After.', 'danger')
        elif search_type == 'expiry_date_before':
            try:
                search_date = datetime.strptime(search_query, '%Y-%m-%d')
                products  = Product.query.filter(Product.expiry_date <= search_date).all()
            except ValueError:
                flash('Invalid date format for Expiry Date Before.', 'danger')
        elif search_type == 'price_above':
            try:
                search_price = float(search_query)
                products  = Product.query.filter(Product.rate_per_unit > search_price).all()
            except ValueError:
                flash('Invalid price format for Price Above.', 'danger')
        elif search_type == 'price_below':
            try:
                search_price = float(search_query)
                products  = Product.query.filter(Product.rate_per_unit < search_price).all()
            except ValueError:
                flash('Invalid price format for Price Below.', 'danger')

    return render_template('search_home.html', categories=categories, products=products,categories1=categories1,products1=products1)


@app.route('/add_to_cart/<int:product_id>', methods=['GET', 'POST'])
@login_required
def add_to_cart(product_id):
    product = Product.query.get_or_404(product_id)
    cart = Cart.query.filter_by(user_id=current_user.id).first()

    if not cart:
        cart = Cart(user_id=current_user.id)
        db.session.add(cart)
        db.session.commit()

    # Check if the product is already in the cart
    cart_item = CartItem.query.filter_by(cart_id=cart.id, product_id=product.id).first()
    if product.quantity >= 1:
        if cart_item:
            cart_item.quantity += 1
            product.quantity -= 1
        else:
            cart_item = CartItem(cart_id=cart.id, product_id=product.id, category_id=product.section_id, quantity=1)
            product.quantity -= 1
        
        db.session.add(cart_item)
        db.session.commit()
        flash('Product added to cart successfully', 'success')
    else:
        flash('Product quantity is insufficient to add to the cart', 'danger')

    return redirect(url_for('home'))

@app.route('/buy/<int:product_id>', methods=['GET', 'POST'])
@login_required
def buy(product_id):
    product = Product.query.get_or_404(product_id)
    cart = Cart.query.filter_by(user_id=current_user.id).first()

    if not cart:
        cart = Cart(user_id=current_user.id)
        db.session.add(cart)
        db.session.commit()

    # Check if the product is already in the cart
    cart_item = CartItem.query.filter_by(cart_id=cart.id, product_id=product.id).first()
    if product.quantity >= 1:
        if cart_item:
            cart_item.quantity += 1
            product.quantity -= 1
        else:
            cart_item = CartItem(cart_id=cart.id, product_id=product.id, category_id=product.section_id, quantity=1)
            product.quantity -= 1
        
        db.session.add(cart_item)
        db.session.commit()
        flash('Product added to cart successfully', 'success')
    else:
        flash('Product quantity is insufficient to add to the cart', 'danger')
    return redirect(url_for('view_cart'))
    
             


@app.route('/view_cart')
@login_required
def view_cart():
    
    # Fetch the user's cart and cart items
    user_cart = Cart.query.filter_by(user_id=current_user.id).first()
    cart_items = user_cart.items if user_cart else []

    # Create a list to store cart items with product details
    cart_items_with_product = []

    # Calculate the total amount for each cart item and store it
    total_amount = 0

    for cart_item in cart_items:
        product = Product.query.get(cart_item.product_id)
        item_total = product.rate_per_unit * cart_item.quantity
        total_amount += item_total

        cart_items_with_product.append({
            "cart_item": cart_item,
            "product": product,
            "item_total": item_total
        })

    return render_template('view_cart.html', cart_items=cart_items_with_product, total_amount=total_amount)

@app.route('/remove_from_cart/<int:cart_item_id>')
@login_required
def remove_from_cart(cart_item_id):
    cart_item = CartItem.query.get_or_404(cart_item_id)

    # Check if the cart item belongs to the current user
    if cart_item.cart.user_id == current_user.id:
        product = cart_item.product
        product.quantity += cart_item.quantity  # Increase stock_quantity
        db.session.delete(cart_item)
        db.session.commit()
        flash('Item removed from the cart', 'success')
    else:
        flash('You do not have permission to remove this item from the cart', 'danger')

    return redirect(url_for('view_cart'))

@app.route('/user/add_quantity_to_cart/<int:cart_item_id>', methods=['POST'])
@login_required
def add_quantity_to_cart(cart_item_id):
    # Fetch the cart item
    cart_item = CartItem.query.get_or_404(cart_item_id)
    product = cart_item.product
    if product.quantity >= 1:
        product.quantity -= 1
        # Increment the quantity
        cart_item.quantity += 1
        db.session.commit()
    else:
        flash("insaficient Product in shop ",'danger')
    # Redirect back to the cart page
    return redirect(url_for('view_cart'))


@app.route('/user/remove_quantity_to_cart/<int:cart_item_id>', methods=['POST'])
@login_required
def remove_quantity_to_cart(cart_item_id):
    # Fetch the cart item
    cart_item = CartItem.query.get_or_404(cart_item_id)
    product = cart_item.product
    if cart_item.quantity >= 1:
        product.quantity += 1
        # Increment the quantity
        cart_item.quantity -= 1
        db.session.commit()
    else:
        flash("insaficient Cart item ",'danger')
    # Redirect back to the cart page
    return redirect(url_for('view_cart'))




@app.route('/user/checkout')
@login_required
def checkout():
    # Assuming you have a cart for the current user
    cart = Cart.query.filter_by(user_id=current_user.id).first()

    if not cart:
        flash('Your cart is empty. Add items to your cart before checkout.', 'danger')
        return redirect(url_for('view_cart'))

    # Calculate the total amount of the items in the cart
    total_amount = 0
    items_to_remove = []
    checkout_date = datetime.now()

    for cart_item in cart.items:
        product = cart_item.product
        total_amount += product.rate_per_unit * cart_item.quantity
        if total_amount >=2000:
            total_amount = total_amount-500
        items_to_remove.append(cart_item)
        shopping_list_item = ShoppingList(
            user_id=current_user.id,
            product_id=product.id,
            category_id=product.section_id,
            quantity=cart_item.quantity,
            product_name=product.name,
            product_rate_per_unit=product.rate_per_unit,
            category_name=product.section.name,  
            checkout_date=checkout_date
        )
        db.session.add(shopping_list_item)
    db.session.commit()
    # Remove checked-out products from the cart
    for cart_item in items_to_remove:
        cart.items.remove(cart_item)
        db.session.delete(cart_item)

    db.session.commit()

    return render_template('checkout_summary.html', total_amount=total_amount)
    
from collections import defaultdict
@app.route('/user/shopping_history')
@login_required  
def shopping_history():
    shopping_history = ShoppingList.query.filter_by(user_id=current_user.id).all()
    shopping_totals = defaultdict(float)

    # Group shopping history entries by checkout date and calculate total amounts
    for item in shopping_history:
        checkout_date = item.checkout_date.strftime('%Y-%m-%d')  # Format date as a string
        total_amount = item.quantity * item.product_rate_per_unit
        shopping_totals[checkout_date] += total_amount

    return render_template('shopping_history.html', shopping_history=shopping_history,shopping_totals=shopping_totals)


'''
@app.route('/product/<int:product_id>', methods=['GET', 'POST'])
@login_required
def product_details(product_id):
    product = Product.query.get_or_404(product_id)
    
    if request.method == 'POST':
        # Process add-to-cart functionality here
        current_user.cart.append(product)
        db.session.commit()
        flash(f'{product.name} added to your cart.', 'success')
    
    return render_template('product_details.html', product=product)

@app.route('/cart')
@login_required
def cart():
    cart_products = current_user.cart
    return render_template('cart.html', cart_products=cart_products)

@app.route('/checkout', methods=['POST'])
@login_required
def checkout():
    cart_products = current_user.cart
    total_price = sum(product.rate_per_unit for product in cart_products)
    
    # Create an order and update product quantities, etc.
    order = Order(user=current_user, products=cart_products)
    for product in cart_products:
        product.quantity -= 1
    current_user.cart = []
    db.session.add(order)
    db.session.commit()
    
    flash('Order placed successfully. Thank you!', 'success')
    return redirect(url_for('home'))
'''