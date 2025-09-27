from asyncio.log import logger
import datetime
import traceback
import mysql.connector
from src.database.database import Database
from src.database.queries import Queries

class AuthHandler:
    @staticmethod
    def register_user(username, password):
        """
        Registra um novo usuário no sistema
        Retorna: (success, message, user_id)
        """
        try:
            connection = Database.get_connection()
            cursor = connection.cursor()
            
            # Verifica se usuário já existe
            cursor.execute(Queries.CHECK_USER_EXISTS, (username,))
            if cursor.fetchone():
                return False, "Usuário já existe. Escolha outro nome.", None
            
            # Validações básicas
            if len(username) < 3:
                return False, "Nome de usuário deve ter pelo menos 3 caracteres", None
            
            if len(password) < 6:
                return False, "Senha deve ter pelo menos 6 caracteres", None
            
            # Cria novo usuário
            cursor.execute(Queries.CREATE_USER, (username, password))
            user_id = cursor.lastrowid
            
            # Registra o status inicial do usuário (offline)
            cursor.execute(Queries.CREATE_USER_STATUS, (user_id, False))
            
            connection.commit()
            
            return True, "Usuário registrado com sucesso!", user_id
            
        except mysql.connector.Error as e:
            error_message = f"Erro no registro: {e}"
            print(error_message)
            return False, error_message, None
        except Exception as e:
            error_message = f"Erro inesperado: {e}"
            print(error_message)
            return False, error_message, None
    
    @staticmethod
    def authenticate_user(username, password):
        """
        Autentica um usuário existente
        Retorna: (success, message, user_id)
        """
        try:
            connection = Database.get_connection()
            cursor = connection.cursor(dictionary=True)
            
            cursor.execute(Queries.GET_USER, (username, password))
            user = cursor.fetchone()
            
            if user:
                user_id = user['id']
                cursor.execute(Queries.UPDATE_USER_STATUS, (user_id, True, None))
                connection.commit()
                return True, "Login realizado com sucesso", user_id
            else:
                return False, "Usuário não encontrado", None
                
        except Exception as e:
            logger.error(f"Erro no login: {e}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            return False, f"Erro interno: {str(e)}", None
        
    @staticmethod
    def logout_user(user_id):
        """
        Faz logout do usuário (atualiza status para offline)
        Retorna: (success, message)
        """
        try:
            connection = Database.get_connection()
            cursor = connection.cursor()
            cursor.execute(Queries.UPDATE_USER_STATUS, (False, datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'), user_id))
            connection.commit()
            
            return True, "Logout realizado com sucesso"
            
        except mysql.connector.Error as e:
            error_message = f"Erro no logout: {e}"
            print(error_message)
            return False, error_message
    
    @staticmethod
    def get_user_id(username):
        """
        Obtém o ID do usuário pelo username
        Retorna: user_id ou None se não encontrado
        """
        try:
            connection = Database.get_connection()
            cursor = connection.cursor()
            
            cursor.execute(Queries.GET_USER_ID, (username,))
            user = cursor.fetchone()
            
            return user[0] if user else None
            
        except mysql.connector.Error as e:
            print(f"Erro ao buscar user_id: {e}")
            return None