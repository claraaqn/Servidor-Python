import mysql.connector
from mysql.connector import Error
from src.config.config import Config
import time
import logging

logger = logging.getLogger(__name__)

class Database:
    _connection = None
    _connection_attempts = 0
    _max_attempts = 3
    
    @staticmethod
    def get_connection():
        if Database._connection is None or not Database._connection.is_connected():
            Database._connect_with_retry()
        return Database._connection
    
    @staticmethod
    def _connect_with_retry():
        for attempt in range(Database._max_attempts):
            try:
                logger.info(f"🔗 Tentativa {attempt + 1} de conexão com o banco de dados...")
                
                # USAR A MESMA CONEXÃO DO TESTE QUE FUNCIONOU
                Database._connection = mysql.connector.connect(
                    host=Config.DB_HOST,
                    port=Config.DB_PORT,
                    database=Config.DB_NAME,
                    user=Config.DB_USER,
                    password=Config.DB_PASSWORD,
                    autocommit=True
                )
                
                if Database._connection.is_connected():
                    db_info = Database._connection.get_server_info()
                    logger.info(f"✅ Conexão com banco de dados estabelecida (MySQL v{db_info})")
                    Database._connection_attempts = 0
                    return
                else:
                    raise Error("Falha na conexão")
                    
            except Error as e:
                Database._connection_attempts += 1
                logger.error(f"❌ Erro ao conectar com banco de dados (tentativa {attempt + 1}/{Database._max_attempts}): {e}")
                
                if attempt < Database._max_attempts - 1:
                    wait_time = 2 ** attempt
                    logger.info(f"⏳ Aguardando {wait_time} segundos antes de tentar novamente...")
                    time.sleep(wait_time)
                else:
                    logger.error("💥 Falha ao conectar com o banco de dados após várias tentativas")
                    raise
    
    @staticmethod
    def close_connection():
        if Database._connection and Database._connection.is_connected():
            Database._connection.close()
            Database._connection = None
            logger.info("🔌 Conexão com banco de dados fechada")
    
    @staticmethod
    def check_connection():
        try:
            if Database._connection and Database._connection.is_connected():
                cursor = Database._connection.cursor()
                cursor.execute("SELECT 1")
                cursor.close()
                return True
            return False
        except Error:
            return False
    
    @staticmethod
    def test_connection():
        """Testa a conexão e retorna informações detalhadas"""
        try:
            connection = mysql.connector.connect(
                host=Config.DB_HOST,
                port=Config.DB_PORT,
                database=Config.DB_NAME,
                user=Config.DB_USER,
                password=Config.DB_PASSWORD
            )
            
            if connection.is_connected():
                # Obter informações do servidor
                cursor = connection.cursor()
                cursor.execute("SELECT VERSION()")
                version = cursor.fetchone()[0]
                
                cursor.execute("SHOW TABLES")
                tables = [table[0] for table in cursor.fetchall()]
                
                cursor.close()
                connection.close()
                
                return {
                    'success': True,
                    'version': version,
                    'tables': tables,
                    'message': f'Conectado ao MySQL {version} - {len(tables)} tabelas encontradas'
                }
            else:
                return {'success': False, 'message': 'Falha na conexão'}
                
        except Error as e:
            return {'success': False, 'message': str(e)}