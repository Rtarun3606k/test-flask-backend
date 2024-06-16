from flask import Flask ,request ,jsonify,render_template
from flask_jwt_extended import create_access_token,JWTManager,jwt_required,get_jwt_identity
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from datetime import timedelta
import bcrypt
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
CORS(app)

# Setup the Flask-JWT-Extended extension
app.config["JWT_SECRET_KEY"] = "super-secret"  # Change this!
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://neondb_owner:JnCXP1E6Tyzt@ep-calm-flower-a5bdgi5t.us-east-2.aws.neon.tech/neondb?sslmode=require'
db = SQLAlchemy(app)
jwt = JWTManager(app)



# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    


    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    
class Blogs(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    author = db.relationship('User', backref=db.backref('blogs', lazy=True))

    def __repr__(self):
        return f'<Blog {self.title}>'


@app.route("/")
def home():
    return render_template("home.html")


@app.route("/d",methods=["GET"])
@jwt_required() 
def func():
    user_data = User.query.all()
    user_list = []
    current_user = get_jwt_identity()
    # print("current user",current_user)
    for user in user_data:
    
        user_dict = {
            "name": user.username,
            
        }
        user_list.append(user_dict)
    return jsonify(users=user_list)

@app.route("/blogs",methods=["GET"])
def blogs():
    blogs = Blogs.query.all()
    blog_list = [{"id": blog.id, "title": blog.title,"author":blog.author.username ,"content":blog.content} for blog in blogs]
    return jsonify({"blogs": blog_list})

@app.route("/blogs/<int:id>", methods=["GET"])
def blogs_id(id):
    blog = Blogs.query.filter_by(id=id).first()
    if blog:
        blog_data = {
            "id": blog.id,
            "title": blog.title,
            "author": blog.author.username,
            "content": blog.content
        }
        return jsonify({"blog": blog_data})
    else:
        return jsonify({"error": "Blog not found"}), 404
    

@app.route("/blog_update/<int:id>",methods=["POST"])
@jwt_required()
def update_blog(id):
    update_content = request.json.get("update_content",None)
    blog = Blogs.query.filter_by(id=id).first()
    current_user = get_jwt_identity()
    user_check = User.query.filter_by(username=current_user).first()
    if(user_check.id == blog.author_id):
        blog.content = update_content
        try:
            db.session.add(blog)
            db.session.commit()
            return jsonify({"msg":f"updated sucessfully"})
        except Exception as e:
            return jsonify({"msg":f"{e}"})
    else:
            return jsonify({"msg":f"not quthorized to delete"})
    

@app.route("/user_name_fetch",methods=["GET"])
@jwt_required()
def fetch_user_name():
    current_user = get_jwt_identity()
    if not current_user:
        # print("k")
        return jsonify({"msg":"not authorized"}),500
    # print("k555")
    return jsonify({"user":current_user}),200



@app.route("/blogs/delete/<int:id>" ,methods=["DELETE"])
@jwt_required()
def delete_blogs(id):
    current_user = get_jwt_identity()
    get_user_id = User.query.filter_by(username=current_user).first()
    delete_data = Blogs.query.filter_by(id=id,author_id=get_user_id.id).first()
    if not delete_data:
        return jsonify({"msg":"your not the author"}),404
    try:
        db.session.delete(delete_data)
        db.session.commit()
        return jsonify({"msg":"blog deleted sucessfully"}),200
    except Exception as e:
        return jsonify({"msg":"was not able to delete blog"}),500

@app.route("/token", methods=["POST"])
def create_token():
    username = request.json.get("username")
    password = request.json.get("password")

    if not username or not password:
        return jsonify({"msg": "Bad username or password"}), 401

    check_user_exists = User.query.filter_by(username=username).first()

    if check_user_exists:
        try:
            # Ensure the password is decoded properly from the database
            hashed_password = check_user_exists.password.encode('utf-8')
            present_password = password.encode("utf-8")

            if bcrypt.checkpw(present_password, hashed_password):
                expires = timedelta(minutes=30)  # Token expiration time
                access_token = create_access_token(identity=username, expires_delta=expires)
                return jsonify(access_token=access_token)
            else:
                return jsonify({"msg": "Invalid password"}), 401
        except ValueError:
            return jsonify({"msg": "Invalid salt"}), 500  # Internal server error for invalid salt

    return jsonify({"msg": "User not found"}), 401

@app.route("/register", methods=["POST"])
def register():
    username = request.json.get("username", None)
    password = request.json.get("password", None)

    if not username or not password:
        return jsonify({"msg": "Username or password missing"}), 400

    check_user_exists = User.query.filter_by(username=username).first()
    if check_user_exists:
        return jsonify({"msg": "User already exists"}), 409

    if password is None:
        return jsonify({"msg": "Password cannot be None"}), 400

    bytes_password = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(bytes_password, salt)

    new_user = User(username=username, password=hashed_password.decode('utf-8'))  # Store as string

    try:
        db.session.add(new_user)
        db.session.commit()
    except Exception as e:
        return jsonify({"msg": f"The following error occurred: {e}"}), 401

    return jsonify({"msg": "User created successfully"}), 201



@app.route("/upload_blogs", methods=["POST"])
@jwt_required()
def upload_blogs():
    blog_data = request.json.get("blog_data", None)
    blog_title = request.json.get("blog_title", None)
    current_user = get_jwt_identity()
    author = User.query.filter_by(username=current_user).first()
    
    create_blog = Blogs(title=blog_title, content=blog_data, author_id=author.id)
    try:
        db.session.add(create_blog)
        db.session.commit()
        return jsonify({"msg": "Blog created successfully"}), 200
    except Exception as e:
        # print(e)
        return jsonify({"msg": "Error creating blog"}), 409





 

# if __name__ == "__main__":
#     with app.app_context():
#         db.create_all()
#     app.run(debug=True ,port=5000)
