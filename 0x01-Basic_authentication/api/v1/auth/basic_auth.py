#!/usr/bin/env python3
"""
Basic auth module for the API
"""
import base64
from api.v1.auth.auth import Auth
from typing import Tuple, TypeVar


class BasicAuth(Auth):
    """Basic auth"""

    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
        """returns the Base64 part of the Authorization header
        for a Basic Authentication:"""
        return None if (authorization_header is None
                        or type(authorization_header) is not str
                        or not authorization_header.startswith("Basic "))\
            else authorization_header.split("Basic")[-1].strip()

    def decode_base64_authorization_header(self,
                                           base64_authorization_header: str)\
            -> str:
        """returns the decoded value
        of a Base64 string base64_authorization_header"""
        if (base64_authorization_header is None
                or type(base64_authorization_header) is not str):
            return None
        try:
            decoded = base64.b64decode(base64_authorization_header)
            return decoded.decode("utf-8")
        except BaseException:
            return None

    def extract_user_credentials(self,
                                 decoded_base64_authorization_header: str)\
            -> Tuple[str, str]:
        """in the class BasicAuth that returns the user email and password
        from the Base64 decoded value."""
        return (None, None)\
            if (decoded_base64_authorization_header is None
                or type(decoded_base64_authorization_header) is not str
                or ":" not in decoded_base64_authorization_header)\
            else tuple(decoded_base64_authorization_header.split(":", 1))

    def user_object_from_credentials(self,
                                     user_email: str,
                                     user_pwd: str) -> TypeVar('User'):
        """returns the User instance based on his email and password.
        Args:
            self (_type_): Basic auth instance
            user_email(str): user email
            user_pwd(str): user pwd
        """
        if not (user_email and isinstance(user_email, str) and
                user_pwd and isinstance(user_pwd, str)):
            return None

        try:
            users = User.search({'email': user_email})
        except Exception:
            return None

        for user in users:
            if user.is_valid_password(user_pwd):
                return user

        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """get current user"""
        try:
            auth_header = self.authorization_header(request)
            encoded = self.extract_base64_authorization_header(auth_header)
            decoded = self.decode_base64_authorization_header(encoded)
            email, password = self.extract_user_credentials(decoded)
            return self.user_object_from_credentials(email, password)
        except Exception:
            return None
