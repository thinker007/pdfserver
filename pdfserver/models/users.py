#!/usr/bin/env python
#coding=utf-8
"""
    models: users.py
    ~~~~~~~~~~~~~
    :license: BSD, see LICENSE for more details.
"""

import hashlib

from datetime import datetime

from werkzeug import cached_property

from flask import abort, current_app

from sqlalchemy import BaseQuery
from flaskext.principal import RoleNeed, UserNeed, Permission

from sqlalchemy import Table, Column, Integer, String
from sqlalchemy.orm import mapper
from sqlalchemy.orm.interfaces import MapperExtension
from sqlalchemy.orm.exc import NoResultFound

from pdfserver.database import metadata, db_session
from pdfserver import app

class UserQuery(BaseQuery):

    def from_identity(self, identity):
        """
        Loads user from flaskext.principal.Identity instance and
        assigns permissions from user.

        A "user" instance is monkeypatched to the identity instance.

        If no user found then None is returned.
        """

        try:
            user = self.get(int(identity.name))
        except ValueError:
            user = None

        if user:
            identity.provides.update(user.provides)

        identity.user = user

        return user
    
    def authenticate(self, login, password):
        
        user = self.filter(db.or_(User.username==login,
                                  User.email==login)).first()

        if user:
            authenticated = user.check_password(password)
        else:
            authenticated = False

        return user, authenticated

    def search(self, key):
        query = self.filter(db.or_(User.email==key,
                                   User.nickname.ilike('%'+key+'%'),
                                   User.username.ilike('%'+key+'%')))
        return query

    def get_by_username(self, username):
        user = self.filter(User.username==username).first()
        if user is None:
            abort(404)
        return user


class User(db.Model):

    __tablename__ = 'users'
    
    query_class = UserQuery

    PER_PAGE = 50
    TWEET_PER_PAGE = 30
    
    MEMBER = 100
    MODERATOR = 200
    ADMIN = 300
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True)
    nickname = db.Column(db.String(20))
    email = db.Column(db.String(100), unique=True, nullable=False)
    _password = db.Column("password", db.String(80), nullable=False)
    role = db.Column(db.Integer, default=MEMBER)
    activation_key = db.Column(db.String(40))
    date_joined = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, default=datetime.utcnow)
    last_request = db.Column(db.DateTime, default=datetime.utcnow)
    block = db.Column(db.Boolean, default=False)

    class Permissions(object):
        
        def __init__(self, obj):
            self.obj = obj
    
        @cached_property
        def edit(self):
            return Permission(UserNeed(self.obj.id)) & admin
  
    def __init__(self, *args, **kwargs):
        super(User, self).__init__(*args, **kwargs)

    def __str__(self):
        return self.nickname
    
    def __repr__(self):
        return "<%s>" % self
    
    @cached_property
    def permissions(self):
        return self.Permissions(self)
  
    def _get_password(self):
        return self._password
    
    def _set_password(self, password):
        self._password = hashlib.md5(password).hexdigest()
    
    password = db.synonym("_password", 
                          descriptor=property(_get_password,
                                              _set_password))

    def check_password(self,password):
        if self.password is None:
            return False        
        return self.password == hashlib.md5(password).hexdigest()
    
    @cached_property
    def provides(self):
        needs = [RoleNeed('authenticated'),
                 UserNeed(self.id)]

        if self.is_moderator:
            needs.append(RoleNeed('moderator'))

        if self.is_admin:
            needs.append(RoleNeed('admin'))

        return needs
    
    @property
    def is_moderator(self):
        return self.role >= self.MODERATOR

    @property
    def is_admin(self):
        return self.role >= self.ADMIN



class UserCode(db.Model):

    __tablename__ = 'usercode'
    
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(20), nullable=False)
    role = db.Column(db.Integer, default=User.MEMBER)
    
    def __init__(self, *args, **kwargs):
        super(UserCode, self).__init__(*args, **kwargs)

    def __str__(self):
        return self.code
    
    def __repr__(self):
        return "<%s>" % self



