#!/usr/bin/env python3
"""DB module
"""
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.session import Session
from sqlalchemy.exc import InvalidRequestError
from sqlalchemy.orm.exc import NoResultFound

from typing import TypeVar

from user import Base, User


class DB:
    """DB class
    """

    def __init__(self) -> None:
        """Initialize a new DB instance
        """
        self._engine = create_engine("sqlite:///a.db", echo=False)
        Base.metadata.drop_all(self._engine)
        Base.metadata.create_all(self._engine)
        self.__session = None

    @property
    def _session(self) -> Session:
        """Memoized session object
        """
        if self.__session is None:
            DBSession = sessionmaker(bind=self._engine)
            self.__session = DBSession()
        return self.__session

    def add_user(self, email: str, hashed_password: str) -> User:
        """Adds New User"""
        try:
            new_user = User()
            new_user.email = email
            new_user.hashed_password = hashed_password
            self._session.add(new_user)
            self._session.commit()
            return new_user
        except Exception:
            self._session.rollback()
            return None

    def find_user_by(self, **arg) -> User:
        """Finds user by arg"""
        try:
            user = self._session.query(User).filter_by(**arg).first()
            if not user:
                raise NoResultFound
            return user
        except InvalidRequestError as e:
            raise e

    def update_user(self, user_id: int, **kwargs) -> User:
        """Updates User data"""
        user = self.find_user_by(id=user_id)
        for k, v in kwargs.items():
            try:
                setattr(user, k, v)
            except AttributeError:
                raise ValueError
        self._session.commit()
