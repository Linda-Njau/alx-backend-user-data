#!/usr/bin/env python3
"""
auth file
"""

from db import DB
from user import User
import bcrypt
from sqlalchemy.orm.exc import NoResultFound
import uuid


class Auth:
    """Auth class to interact with the authentication database.
    """
    def __init__(self):
        self.db = DB()

    def register_user(self, email: str, password: str) -> User:
        """registers a user"""
        try:
            if self.db.find_user_by(email=email):
                raise ValueError("User {} already exists".format(email))
        except NoResultFound:
            hashed_password = _hash_password(password)
            new_user = self.db.add_user(
                email=email, hashed_password=hashed_password)
            return new_user

    def valid_login(self, email: str, password: str) -> bool:
        """Checks for valid login email and password"""
        try:
            user = self.db.find_user_by(email=email)
            if user and bcrypt.checkpw(
                    password.encode('utf8'), user.hashed_password):
                return True
            return False
        except NoResultFound:
            return False

    def create_session(self, email: str) -> str:
        """Create a new session from an email address"""
        try:
            user = self.db.find_user_by(email=email)
            user.session_id = _generate_uuid()
            return user.session_id
        except NoResultFound:
            return None


def _generate_uuid() -> str:
    """Generates a random uuid"""
    new_uuid = uuid.uuid4()
    return str(new_uuid)


def _hash_password(password: str) -> bytes:
    """takes a password and returns bytes"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
