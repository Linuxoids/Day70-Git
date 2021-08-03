from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
# from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from functools import wraps

import forms
from forms import CreatePostForm
from flask_gravatar import Gravatar

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

## LOGIN MANAGER SETUP
login_manager = LoginManager(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


##CONFIGURE TABLES

class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String, nullable=False, unique=True)
    password = db.Column(db.String, nullable=False)
    name = db.Column(db.String())
    is_admin = db.Column(db.Boolean, nullable=False)

    posts = db.relationship("BlogPost", backref="author")
    comments = db.relationship("Comment", backref="author")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    comments = db.relationship("Comment", backref="post")


class Comment(db.Model):
    __tablename__ = "comments"

    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(500), nullable=False)

    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))

# db.create_all()


## Custom Decorators:

def admin_only(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if current_user.is_authenticated and current_user.is_admin:
            return function(*args, **kwargs)
        else:
            return abort(403)
    return wrapper


#
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

#


@app.route('/')
def get_all_posts():
    is_admin = current_user.is_authenticated and current_user.is_admin
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, is_admin=is_admin)


@app.route('/register', methods=["GET", "POST"])
def register():
    form = forms.RegisterForm()

    if request.method == "POST" and form.validate_on_submit():

        email_list = [account.email for account in User.query.all()]
        if form.email.data not in email_list:
            new_user = User(
                email=form.email.data,
                password=generate_password_hash(form.password.data, salt_length=8),
                name=form.name.data,
                is_admin=False
            )
            db.session.add(new_user)
            db.session.commit()

            login_user(new_user)

            flash("Successfully created the account.")
            return redirect(url_for('get_all_posts'))

        else:
            flash(f'This email is already registred. You may want to <a href="' + url_for('login') + '">Log In<a>')

    return render_template("register.html", form=form)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = forms.LoginForm()

    if request.method == "POST" and form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        account = User.query.filter_by(email=email).first()

        if account and check_password_hash(account.password, password):
            login_user(account)

            flash("Successfully logget in.")

            return redirect(url_for('get_all_posts'))
        else:
            flash("Incorrect email or password.")

    return render_template("login.html", form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Successfully logged out.")
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    comment_form = forms.CommentForm()

    if comment_form.validate_on_submit():

        if current_user.is_authenticated:

            comment_text = comment_form.comment_text.data
            new_comment = Comment(
                text=comment_text,
                author=current_user,
                post=BlogPost.query.get(post_id)
            )
            db.session.add(new_comment)
            db.session.commit()

            flash("Commented successfully.")
        else:
            flash("You have to log in before you can comment.")

    is_admin = current_user.is_authenticated and current_user.is_admin

    requested_post = BlogPost.query.get(post_id)
    comments = requested_post.comments
    return render_template("post.html",
                           post=requested_post, is_admin=is_admin, comment_form=comment_form, comments=comments)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>")
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
