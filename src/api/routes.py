"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
import os
from flask import Flask, request, jsonify, Blueprint
from flask_cors import CORS
from flask_jwt_extended import create_access_token, jwt_required, JWTManager, get_jwt_identity
from flask_bcrypt import Bcrypt
from api.models import db, User,Books,Favorites,Review
from api.utils import APIException, generate_sitemap


app = Flask(__name__)
jwt = JWTManager(app)

api = Blueprint('api', __name__)

secret_key = os.urandom(24).hex()
app.config['JWT_SECRET_KEY'] = secret_key

bcrypt = Bcrypt(app)

CORS(api)


@api.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    
    email = data["email"]
    repetido = User.query.filter_by(email=email).first()

    if repetido: 
        return jsonify({"error":"correo registrado"}), 400
    
    password = bcrypt.generate_password_hash(data["password"]).decode('utf-8')

    user = User(email=email,password=password,first_name=data["first_name"],last_name=data["last_name"],phone=data["phone"],location=data["location"],is_active=True)
    
    db.session.add(user)
    db.session.commit()   

    return jsonify({"mensaje":"registro exitoso"})
@api.route("/login", methods=['POST'])
def user_login():
 try:
    data = request.get_json()
    email = data["email"]
    password = data["password"]
    

    if not data or "email" not in data or "password" not in data:
        return jsonify({"message": "Se requieren tanto el correo electrónico como la contraseña"}), 400

    

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "Usuario no encontrado"}), 404

    verify_password = bcrypt.check_password_hash(User.password, password)
    if not verify_password:
        return jsonify({"message": "Credenciales incorrectas"}), 401

    payload = {
        "email": User.email, 
        "first_name": User.first_name, 
        "last_name": User.last_name,
        "phone": User.phone, 
        "location": User.location
    }
    token = create_access_token(identity=user.id, additional_claims=payload)
    return jsonify({"token": token}), 200
 except Exception as e:
    print("Error:", e)
    return jsonify({"message": "Ocurrió un error interno del servidor"}), 500


        
@api.route('/add_review', methods=['POST'])
@jwt_required()
def add_review():
    try:
        data = request.get_json()
        user_id = get_jwt_identity()
        book_id = data["book_id"]
        content = data["content"]

        review = Review(content=content, user_id=user_id, book_id=book_id)
        db.session.add(review)
        db.session.commit()

        return jsonify({"message": "Review added successfully"}), 200
    except Exception as e:
        return jsonify({"message": "An error occurred while adding the review: " + str(e)}), 500
@api.route("/private", methods=["GET"])
@jwt_required()

def private():
    return jsonify({"message":"acceso permitido"}), 200

@api.route("/add_to_favorites", methods=["POST"])
@jwt_required()
def add_to_favorites():
    try:
        data = request.get_json()
        user_id = get_jwt_identity()
        
        
        if not data or "book_id" not in data:
            return jsonify({"message": "Book ID requiered"}), 400

        book_id = data["book_id"]
        book = Books.query.get(book_id)
        if not book:
            return jsonify({"message": "bOOK NOT FOUND"}), 404

        if Favorites.query.filter_by(user_id=user_id, book_id=book_id).first():
            return jsonify({"message": "El libro ya está en tus favoritos"}), 400

        favorite = Favorites(user_id=user_id, book_id=book_id)
        db.session.add(favorite)
        db.session.commit()

        return jsonify({"message": "Book added to favorites"}), 200
    except Exception as e:
        print("Error:", e)
        return jsonify({"message": "Internal error"}), 500

@api.route("/remove_from_favorites/<int:book_id>", methods=["DELETE"])
def remove_from_favorites(book_id):
    data = request.get_json()
    user_id = data['user_id']   # Implementa esta función para obtener el ID del usuario actual.
    if not user_id:
        return jsonify({"message": "User not authenticated"}), 401

    favorite = Favorites.query.filter_by(user_id=user_id, book_id=book_id).first()
    if not favorite:
        return jsonify({"message": "Book not found in favorites"}), 404

    db.session.delete(favorite)
    db.session.commit()

    return jsonify({"message": "Book removed from favorites successfully"}), 200

@api.route("/favorites", methods=["GET"])
@jwt_required()
def user_favorites():
    try:
        user_id = secret_key()  # Obtener el ID del usuario desde el token
        
        user = User.query.get(user_id)
        if not user:
            return jsonify({"message": "Usuario no encontrado"}), 404

        favorites = Favorites.query.filter_by(user_id=user_id).all()
        favorite_books = [favorite.book.serialize() for favorite in favorites]

        return jsonify({"favorites": favorite_books}), 200
    except Exception as e:
        print("Error:", e)
        return jsonify({"message": "Ocurrió un error interno del servidor"}), 500
    
