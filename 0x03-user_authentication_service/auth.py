#!/usr/bin/env python3
"""
auth file
"""

from db import DB
from user import User
import bcrypt
from sqlalchemy.orm.exc import NoResultFound


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
            new_user = self.db.add_user(email=email, hashed_password=hashed_password)
            return new_user
def _hash_password(password: str) -> bytes:
    """takes a password and returns bytes"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
