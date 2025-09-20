import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    DB_HOST = os.getenv('DB_HOST', 'localhost')
    DB_PORT = int(os.getenv('DB_PORT', 3306))
    DB_NAME = os.getenv('DB_NAME', 'chat_db')
    DB_USER = os.getenv('DB_USER', 'chat_user')
    DB_PASSWORD = os.getenv('DB_PASSWORD', '')
    
    SERVER_HOST = os.getenv('SERVER_HOST', 'localhost')
    SERVER_PORT = int(os.getenv('SERVER_PORT', 8080))
    
    DEBUG = os.getenv('DEBUG', 'false').lower() == 'true'