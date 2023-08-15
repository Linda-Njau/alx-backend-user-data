#!/usr/bin/env python3
"""
app file
"""

from flask import Flask, jsonify, request
from auth import Auth

app = Flask(__name__)
AUTH = Auth()


@app.route('/', methods=['GET'])
def message():
    return jsonify({"message": "Bienvenue"})


@app.route('/users', methods=['POST'])
def register_user():
    email = request.form.get("email")
    password = request.form.get("password")
    user = AUTH.register_user(email, password)
    if not user:
        return jsonify({"message": "email already registered"}), 400
    return jsonify({"email": "<registered email>", "message": "user created"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
