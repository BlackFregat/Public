# -*- coding: utf-8 -*-

import hashlib
import datetime
import peewee as pw
from os import system

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

class LicensesLog(BaseModel):
    issuer = pw.ForeignKeyField(User)
    license_timestamp = pw.DateTimeField(default=datetime.datetime.now)

    serial_number = pw.CharField(default='')
    address = pw.CharField(default='')

    hardware_id = pw.CharField()
    config_checksum = pw.CharField()

    config_lock_date = pw.DateField(null=True)
    license_valid_date = pw.DateField(null=True)

    license_file = pw.CharField(null=True)
    signature_file = pw.CharField(null=True)

class PasswordsLog(BaseModel):
    issuer = pw.ForeignKeyField(User)
    date = pw.DateTimeField(default=datetime.datetime.now)
    serial_number = pw.CharField(default='')
    version = pw.CharField(default='')

    date_from = pw.DateField(null=True)
    date_to = pw.DateField(null=True)
    days = pw.IntegerField()

class Journal(BaseModel):
    author = pw.ForeignKeyField(User, null=True)
    ip = pw.CharField(max_length=64)
    timestamp = pw.DateTimeField(default=datetime.datetime.now)
    affected_user = pw.ForeignKeyField(User, null=True, related_name='affected_user')
    affected_license = pw.ForeignKeyField(LicensesLog, null=True, related_name='affected_user')
    affected_password = pw.ForeignKeyField(PasswordsLog, null=True, related_name='affected_password')
    module = pw.IntegerField()
    text = pw.CharField()

    MODULE_AUTH = 0
    MODULE_ADMIN = 1
    MODULE_LICENSE = 2
    MODULE_LOCKER = 3

class Settings(BaseModel):
    name = pw.CharField(primary_key=True)
    value = pw.TextField(null=True)

    SETTING_WELCOME = 'welcome'
    SETTING_VERSION = 'version'

    CURRENT_VERSION = '2'

init_db()
def out(data):
    print 'id', '->', data['id']
    for i, v in dict(data).items():
        if i != 'id':
            print i, '->', v
    print '--------'

def process(Table, lnk = None):
    id = None
    q = Table.select().order_by(Table.id.desc()).dicts()
    for i in xrange(0, len(q), 3):
        system('clear')
        for r in q[i:i+3]:
            out(r)
        ans = raw_input('Enter to next page or id to delete: ')
        if ans != '':
            id = int(ans)
            break
    if id is None:
        return
    system('clear')
    q = Table.select().where(Table.id == id).dicts()
    for r in q:
        out(r)
    if lnk: 
        q = Journal.select().where(lnk == id).dicts()
        for r in q:
            out(r)
    ans = raw_input('Perform delete? (y/n): ')
    if ans == 'y' or ans == 'Y':
        if lnk:
            Journal.delete().where(lnk == id).execute()
        Table.delete().where(Table.id == id).execute()

def deleteAll(Table, lnk = None):
    if lnk:
        Journal.delete().where(lnk.is_null(False)).execute()
    Table.delete().execute()

while True:
    print('')
    print('--- Look and delete 1 record')
    print('1. Locker password history')
    print('2. License history')
    print('3. Journal')
    print('')
    print('--- Delete all')
    print('4. Locker password history')
    print('5. License history')
    print('6. Journal')
    print('')
    print('7. Exit')
    ans = raw_input('Select: ')
    if ans == '1':
        process(PasswordsLog, Journal.affected_password_id)
    elif ans == '2':
        process(LicensesLog, Journal.affected_license_id)
    elif ans == '3':
        process(Journal)
    if ans == '4':
        deleteAll(PasswordsLog, Journal.affected_password_id)
    elif ans == '5':
        deleteAll(LicensesLog, Journal.affected_license_id)
    elif ans == '6':
        deleteAll(Journal)
    elif ans == '7':
        break
