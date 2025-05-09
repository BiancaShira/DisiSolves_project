from flask import Flask , render_template , request ,flash , url_for , redirect, request
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql import func
from utils.software_types import Software_types
from datetime import datetime
from flask_login import UserMixin, login_user, login_manager, LoginManager, login_required, current_user 




app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = f"mysql://root:@localhost:3306/disisolves"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config["SECRET_KEY"] = "BIANCA"
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
        return User.query.get(int(user_id))

@app.route("/")
def index():
    problems = Problems.query.all()
    return render_template("index.html" , problems = problems)

@app.route("/disisolves/admin")
def admin():
    return render_template("./admin/admin.html")


@app.route ("/disisolves/admin/register", methods =["GET" , "POST"])
def register():
    if request.method =="POST":    
        username=request.form.get('username')
        password=request.form.get('password')
        confirm_password=request.form.get("confirm_password")

        user = User.query.filter_by(username=username).first()
        if password != confirm_password:
            flash("Passwords do not match")
            return redirect(url_for('register'))
        if user: 
           flash("Username already exists")
           return redirect(url_for('register'))
        new_user = User(username=username, password=generate_password_hash(password, method='pbkdf2:sha256'))
        db.session.add(new_user)
        db.session.commit() 

        flash("Register successful! Please login.")
        return redirect(url_for('login'))
    
    return render_template("./admin/register.html")
    

@app.route("/disisolves/admin/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        remember = True if request.form.get("remember") else False

        user = User.query.filter_by(username=username).first()
        check_password_hash = User.query.filter_by(password=password).first()


        if not user or not check_password_hash:
            flash("Please check your login details and try again.")
            return redirect(url_for("login"))

        login_user(user, remember=remember)
        return redirect(url_for("admin_dashboard"))  

    return render_template("./admin/login.html")


@app.route("/disisolves/admin/dashboard")
@login_required
def admin_dashboard():
    return render_template("./admin/admin_dashboard.html", username = current_user.username)

@app.route("/disisolves/admin/problems/post" , methods=["GET" , "POST"])
def create_problems():
    if request.method == "POST":
        title = request.form.get('title')
        description = request.form.get('description')
        software_types = request.form.get('software_types') #flash_messages = [Tile Required , description]
        has_error = False
        if not title:
            flash("Title required" , category="error")
            has_error = True
        if not description:
             flash("Description required" , category="error")
             has_error = True
        if not software_types:
            flash("Software Types Required" , category="error")
            has_error = True
        if not has_error:
            db.session.add(Problems(
                title =  title,
                description = description,
                software_types = software_types,
                posted_by = "Bianca"
            ))

            db.session.commit()

            return redirect("/")
    return render_template("admin/post_problems.html")


@app.route("/disisolves/problems/<id>")
def problem_details(id):
    problem = Problems.query.filter_by(id = id).first_or_404()
    return render_template("problem_detail.html" , problem=problem)



@app.route("/disisolves/admin/problems/<id>/edit")
def update_problem():
    return render_template("admin/update_problem.html")


class Problems(db.Model):
    id = db.Column(db.Integer , primary_key=True)
    title=db.Column(db.Text , nullable = False)
    description =db.Column(db.Text , nullable = False)
    software_types =db.Column(db.Enum(Software_types) , nullable = False)
    posted_by =db.Column(db.Text , nullable = False)
    posted_at =db.Column(db.DateTime(), index=True, default=datetime.now)

with app.app_context():
    db.create_all()

class Users(db.Model, UserMixin):
     id = db.Column(db.Integer , primary_key=True)
     username =db.Column(db.String(20) , nullable = False, unique = True)
     password=db.Column(db.String(20), nullable = False)

with app.app_context():
    db.create_all()


