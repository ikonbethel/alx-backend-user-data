#!/usr/bin/env python3
"""
Auth module for the API
"""
from flask import request
from typing import TypeVar, List


class Auth:
    """Auth class"""
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        returns True if the path is not in the list of strings excluded_paths
        """
        if path is None or excluded_paths in [[], None]:
            return True
        path = path if path.endswith('/') else path + '/'
        if any("*" in expath for expath in excluded_paths):
            return not all(pat.replace("*", "") in path for pat in excluded_paths)
        return not path in excluded_paths

    def authorization_header(self, request=None) -> str:
        """ validate all requests to secure the API"""
        if request is None:
            return None
        return request.headers.get("Authorization")

    def current_user(self, request=None) -> TypeVar('User'):
        """returns None"""
        return None
    
    def session_cookie(self, request=None):
        """returns a cookie value from a request"""
        if request is None:
            return None
        from os import getenv
        cookie_name = getenv("SESSION_NAME")
        return request.cookies.get(cookie_name)

