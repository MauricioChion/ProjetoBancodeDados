from flask import Flask, request, jsonify
from models.user import User
from database import db
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
import bcrypt
import os

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "you_secret_key")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URI", "mysql+pymysql://root:admin123@127.0.0.1:3306/flask-crud")

login_manager = LoginManager()
db.init_app(app)
login_manager.init_app(app)

login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"message": "Usuário e senha são obrigatórios"}), 400

    user = User.query.filter_by(username=username).first()

    if user and bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
        login_user(user)
        return jsonify({"message": "Credenciais realizadas com sucesso"}), 200

    return jsonify({"message": "Credenciais inválidas"}), 400

@app.route("/logout", methods=["GET"])
@login_required
def logout():
    logout_user()
    return jsonify({"message": "Logout realizado com sucesso"}), 200

@app.route("/user", methods=["POST"])
def create_user():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"message": "Dados inválidos"}), 400

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    user = User(username=username, password=hashed_password, role="user")
    db.session.add(user)
    db.session.commit()
    return jsonify({"message": "Usuário cadastrado com sucesso"}), 201

@app.route("/user/<int:id_user>", methods=["GET"])
@login_required
def read_user(id_user):
    user = User.query.get(id_user)

    if user:
        return jsonify({"username": user.username}), 200
    
    return jsonify({"message": "Usuário não encontrado"}), 404

@app.route("/user/<int:id_user>", methods=["PUT"])
@login_required
def update_user(id_user):
    data = request.json
    user = User.query.get(id_user)

    if current_user.id != id_user and current_user.role == "user":
        return jsonify({"message": "Operação não permitida"}), 403    

    if user:
        if data.get("password"):
            user.password = bcrypt.hashpw(data.get("password").encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        db.session.commit()
        return jsonify({"message": f"Usuário {id_user} atualizado com sucesso"}), 200
    
    return jsonify({"message": "Usuário não encontrado"}), 404

@app.route("/user/<int:id_user>", methods=["DELETE"])
@login_required
def delete_user(id_user):
    if current_user.role != "admin":
        return jsonify({"message": "Operação não permitida"}), 403
    
    if id_user == current_user.id:
        return jsonify({"message": "Deleção não permitida"}), 403

    user = User.query.get(id_user)

    if user:
        db.session.delete(user)
        db.session.commit()
        return jsonify({"message": f"Usuário {id_user} deletado com sucesso"}), 204
    
    return jsonify({"message": "Usuário não encontrado"}), 404

if __name__ == "__main__":
    app.run(debug=True)