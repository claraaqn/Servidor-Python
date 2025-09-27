import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Configurações do Banco de Dados
    DB_HOST = os.getenv('DB_HOST', 'localhost')
    DB_PORT = int(os.getenv('DB_PORT', 3306))
    DB_NAME = os.getenv('DB_NAME', 'chat_db')
    DB_USER = os.getenv('DB_USER', 'chat_user')
    DB_PASSWORD = os.getenv('DB_PASSWORD', '')
    
    # Configurações do Servidor DUAL
    TCP_HOST = os.getenv('TCP_HOST', '0.0.0.0')
    TCP_PORT = int(os.getenv('TCP_PORT', 8081))
    WS_HOST = os.getenv('WS_HOST', '0.0.0.0')
    WS_PORT = int(os.getenv('WS_PORT', 8080))
    
    DEBUG = os.getenv('DEBUG', 'false').lower() == 'true'
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')