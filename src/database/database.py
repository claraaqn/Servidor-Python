import mysql.connector
from mysql.connector import Error
from src.config.config import Config 

class Database:
    _connection = None
    
    @staticmethod
    def get_connection():
        if Database._connection is None or not Database._connection.is_connected():
            try:
                Database._connection = mysql.connector.connect(
                    host=Config.DB_HOST,
                    port=Config.DB_PORT,
                    database=Config.DB_NAME,
                    user=Config.DB_USER,
                    password=Config.DB_PASSWORD
                )
                print("Conexão com banco de dados estabelecida")
            except Error as e:
                print(f"Erro ao conectar com banco de dados: {e}")
                raise
        return Database._connection
    
    @staticmethod
    def close_connection():
        if Database._connection and Database._connection.is_connected():
            Database._connection.close()
            print("Conexão com banco de dados fechada")