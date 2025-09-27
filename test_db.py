import mysql.connector
from dotenv import load_dotenv
import os

load_dotenv()

def test_database_connection():
    try:
        connection = mysql.connector.connect(
            host=os.getenv('DB_HOST', 'localhost'),
            port=int(os.getenv('DB_PORT', 3306)),
            user=os.getenv('DB_USER', 'chat_user'),
            password=os.getenv('DB_PASSWORD', 'chat_password'),
            database=os.getenv('DB_NAME', 'chat_db')
        )
        
        if connection.is_connected():
            print("✅ Conexão com o banco de dados bem-sucedida!")
            
            # Testar se as tabelas existem
            cursor = connection.cursor()
            cursor.execute("SHOW TABLES")
            tables = cursor.fetchall()
            print("📊 Tabelas no banco de dados:")
            for table in tables:
                print(f"   - {table[0]}")
            
            cursor.close()
            connection.close()
            return True
            
    except mysql.connector.Error as e:
        print(f"❌ Erro ao conectar ao banco de dados: {e}")
        return False

if __name__ == "__main__":
    test_database_connection()