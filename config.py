import os

class Config:
    MYSQL_HOST = os.environ.get('MYSQL_HOST') or 'localhost'
    MYSQL_USER = os.environ.get('MYSQL_USER') or 'root'
    MYSQL_PASSWORD = os.environ.get('MYSQL_PASSWORD') or ''
    MYSQL_DB = os.environ.get('MYSQL_DB') or 'network_mgmt'

    SECRET_KEY = os.environ.get('SECRET_KEY') or 'diplomski-rad-mona-2026'