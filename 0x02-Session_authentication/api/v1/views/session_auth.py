#!/usr/bin/env python3
"""
Session auth routes for the API
"""
from api.v1.app import app, request, jsonify, auth
from typing import Tuple
from models.user import User


@app.route("/auth_session/login", methods=["POST"], strict_slashes=False)
def login_session() -> Tuple[str, int]:
	"""Login route"""
	email = request.form.get("email")
	if email is None or len(email.strip()) == 0:
		return jsonify({ "error": "email missing" }), 400
	password = request.form.get("password")
	if password is None or len(password.strip()) == 0:
		return jsonify({ "error": "password missing" }), 400
	try:
		user = User.search({'email': email})
	except Exception:
		return jsonify({ "error": "no user found for this email" }), 404
	