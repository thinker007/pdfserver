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

from sqlalchemy import Table, Column, Integer, String,DateTime,Boolean
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


class User(object):
    query = db_session.query_property()
    MEMBER = 100
    MODERATOR = 200
    ADMIN = 300
    class Permissions(object):
        
        def __init__(self, obj):
            self.obj = obj
    
        @cached_property
        def edit(self):
            return Permission(UserNeed(self.obj.id)) & admin
  
    def __init__(self,id=None,email=None,password=None,date_joined=None,last_login=None):
        self.id = id
        self.email = email
        self._password = password
        self.date_joined = date_joined
        self.last_login = last_login

    def __str__(self):
        return self.email
    
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



class UserCode(object):

    def __init__(self, id=None,code=None,role=User.MEMBER):
        self.id = id
        self.code = code
        self.role = role

    def __str__(self):
        return self.code
    
    def __repr__(self):
        return "<%s>" % self

users = Table( 'users',metadata,
    Column('id', Integer, primary_key=True),
#    Column('username',String(20),unique=True),
#    Column('nickname',String(20)),
    Column('email',String(100),unique=True,nullable=False),
    Column('_password',String(80),nullable=False),
#    Column('role',Integer,default=User.MEMBER),
    Column('activation_key',String(40),),
    Column('date_joined',DateTime,default=datetime.utcnow),
    Column('last_login',DateTime,default=datetime.utcnow),
#    Column('last_request',DateTime,default=datetime.utcnow),
#    Column('block',Boolean,default=False),
    # Use AUTOINCREMENT for sqlite3 to yield globally unique ids
    #   -> new ids cannot take on ids of deleted items, security issue!
    sqlite_autoincrement=True,
    )
mapper(User, users)
usercodes = Table('usercodes',metadata,
    Column('id',Integer,primary_key=True),
    Column('code',String(20),nullable=True),
    Column('role',Integer,default=User.MEMBER), 
    sqlite_autoincrement=True,
    )
mapper(UserCode, usercodes)
