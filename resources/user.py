from datetime import datetime

from flask import jsonify
from flask.views import MethodView
from flask_smorest import Blueprint, abort
from passlib.hash import pbkdf2_sha256
from flask_jwt_extended import create_access_token, get_jwt_identity, create_refresh_token, jwt_required, get_jwt

from blocklist import BLOCKLIST
from db import db
from models import UserModel
from models import BlockListModel
from schemas import UserSchema

blp = Blueprint("users", __name__, description="Operation On Stores")


@blp.route("/register")
class UserRegister(MethodView):
    @blp.arguments(UserSchema)
    def post(self, user_data):
        if UserModel.query.filter(UserModel.username == user_data["username"]).first():
            abort(409, message="A user with that username already exists.")

        user = UserModel(
            username=user_data["username"],
            password = pbkdf2_sha256.hash(user_data["password"])
        )
        db.session.add(user)
        db.session.commit()

        return {"message": "User created successfully"}, 201


@blp.route("/login")
class UserLogin(MethodView):
    @blp.arguments(UserSchema)
    def post(self, user_data):
        user = UserModel.query.filter(
            UserModel.username == user_data["username"]
        ).first()

        if user and pbkdf2_sha256.verify(user_data["password"], user.password):
            access_token = create_access_token(identity=user.id, fresh=True)
            refresh_token = create_refresh_token(identity=user.id)
            return {"access_token": access_token, "refresh_token": refresh_token}

        abort(401, message="Invalid credentials.")


@blp.route("/refresh")
class TokenRefresh(MethodView):
    @jwt_required(refresh=True)
    def post(self):
        current_user = get_jwt_identity()
        new_token = create_access_token(identity=current_user, fresh=False)

        # This ensures that you only use the none fresh token only once.
        jti = get_jwt()['jti']
        revoked_token = BlockListModel(jti=jti, revoked_on=datetime.utcnow())
        db.session.add(revoked_token)
        db.session.commit()

        return {"access_token": new_token}


@blp.route("/logout")
class UserLogout(MethodView):
    # This works with a list as a database.
    @jwt_required()
    def post(self):
        jti = get_jwt()['jti']
        revoked_token = BlockListModel(jti=jti, revoked_on=datetime.utcnow())
        db.session.add(revoked_token)
        db.session.commit()
        return jsonify({"message": "Successfully logged out."}), 200


@blp.route("/user/<int:user_id>")
class User(MethodView):
    @blp.response(200, UserSchema)
    def get(self, user_id):
        user = UserModel.query.get_or_404(user_id)
        return user

    def delete(self, user_id):
        user = UserModel.query.get_or_404(user_id)
        db.session.delete(user)
        db.session.commit()
        return {"message": "User deleted."}, 200
