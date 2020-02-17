# -*- coding: utf-8 -*-

import hashlib
import datetime
import peewee as pw

database_proxy = pw.Proxy()

def wrap_handler(func):
    def wrapped(*args, **kwargs):
        database_proxy.connect(reuse_if_open=True)
        try:
            return func(*args, **kwargs)
        except:
            database_proxy.close()
            raise

    return wrapped


@wrap_handler
def database_wrapper(next_handler, *args, **kwargs):
    if not next_handler:
        return next_handler
    return next_handler(*args, **kwargs)

def hash_pass(login, password):
    return hashlib.sha512(login + password + login).hexdigest()

class BaseModel(pw.Model):
    """Base model class."""
    class Meta:
        database = database_proxy

def init_db():
    """Initializes database."""
    
    user = 'license_gen'
    password = 'license_gen'
    dbname = 'license_gen'
    host = '127.0.0.1'
    port = 5432
    db = pw.PostgresqlDatabase(dbname, user=user, password=password,
                                 sslmode='disable', host=host, port=port)
                                 
    database_proxy.initialize(db)

class User(BaseModel):
    login = pw.CharField(max_length=128)
    is_domain = pw.BooleanField(default=False)
    built_in = pw.BooleanField(default=False)
    password = pw.CharField(max_length=256, null=True)

    is_basic = pw.BooleanField(default=False)
    is_advanced = pw.BooleanField(default=False)
    is_log_reader = pw.BooleanField(default=False)
    is_admin = pw.BooleanField(default=False)
    has_locker = pw.BooleanField(default=False)
    has_locker_history = pw.BooleanField(default=False)

    created_by = pw.ForeignKeyField('self', related_name='stuff', null=True)
    user_timestamp = pw.DateTimeField(default=datetime.datetime.now)

    is_deleted = pw.BooleanField(default=False)

init_db()
login = raw_input('Login: ')
passw = raw_input('Password: ')
User.update(password = hash_pass(login, passw)).where(User.login == login).execute()
