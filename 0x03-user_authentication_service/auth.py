#!/usr/bin/env python3
"""Auth Module"""
import bcrypt
from db import DB
from user import User
from typing import TypeVar, Union
from sqlalchemy.orm.exc import NoResultFound


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """takes mandatory email and password string arguments
        and returns a User object."""
        try:
            user = self._db.find_user_by(email=email)
            if user:
                raise ValueError(f"User {email} already exists.")
        except NoResultFound:
            hashed_password = _hash_password(password)
            return self._db.add_user(email, hashed_password)

    def valid_login(self, email: str, password: str) -> bool:
        """Validates user credentials"""
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return False
        if not bcrypt.checkpw(password.encode("utf-8"), user.hashed_password):
            return False
        return True

    def create_session(self, email: str) -> str:
        """takes an email string argument
        and returns the session ID as a string."""
        try:
            user = self._db.find_user_by(email=email)
            session_id = _generate_uuid()
            self._db.update_user(user.id, session_id=session_id)
            return session_id
        except NoResultFound:
            return None

    def get_user_from_session_id(self, session_id: str)\
            -> Union[TypeVar("User"), None]:
        """takes a single session_id string argument
        and returns the corresponding User or None."""
        if session_id:
            try:
                user = self._db.find_user_by(session_id=session_id)
                return user
            except NoResultFound:
                return None
        return None

    def destroy_session(self, session_id: str) -> Union[TypeVar("User"), None]:
        """takes a single session_id string argument
        and destroys the session."""
        if session_id:
            self._db.update_user(user_id, session_id=None)
        return None

    def get_reset_password_token(self, email: str) -> str:
        """takes an email string argument and returns a string."""
        try:
            reset_token = _generate_uuid()
            user = self._db.find_user_by(email=email)
            self._db.update_user(user.id, reset_token=reset_token)
            return reset_token
        except NoResultFound:
            raise ValueError()

    def update_password(self, reset_token: str, password: str) -> None:
        """takes reset_token string argument and a password string argument
        and returns None."""
        try:
            user = self._db.find_user_by(reset_token=reset_token)
            hashed_password = _hash_password(password)
            self._db.update_user(user.id, hashed_password=hashed_password,
                                 reset_token=None)
        except NoResultFound:
            raise ValueError()
        return None


def _hash_password(password: str) -> bytes:
    """takes in a password string arguments and returns bytes.
    The returned bytes is a salted hash
    of the input password, hashed with bcrypt.hashpw."""
    password_bytes = password.encode("utf-8")
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password_bytes, salt)
    return hashed_password


def _generate_uuid() -> str:
    """GEnerates a new UUID"""
    from uuid import uuid4

    return str(uuid4())
