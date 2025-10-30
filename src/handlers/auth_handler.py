from asyncio.log import logger
import datetime
import os
import traceback
import mysql.connector
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import secrets
import base64
from src.database.database import Database
from src.database.queries import Queries

class AuthHandler:
    
    _ph = PasswordHasher()
    
    @staticmethod
    def register_user(username, password, public_key, salt):
        """
        Registra usuário - recebe password já hasheado com Argon2
        """
        try:
            con = Database.get_connection()
            cursor = con.cursor()

            cursor.execute(Queries.CHECK_USER_EXISTS, (username,))
            if cursor.fetchone():
                return False, "Usuário já existe", None
            
            salt = os.urandom(16)
            salt_b64 = base64.b64encode(salt).decode('utf-8')
            
            from argon2 import PasswordHasher
            ph = PasswordHasher()
            hashed_password = ph.hash(password + salt_b64)
            
            cursor.execute(Queries.CREATE_USER, (username, hashed_password, public_key, salt_b64))
            user_id = cursor.lastrowid
            
            cursor.execute(Queries.CREATE_USER_STATUS, (user_id, False))
            con.commit()
            
            return True, "register_response", user_id
        except Exception as e:
            return False, f"Erro: {e}", None

    @staticmethod
    def get_user_salt(username):
        """
        Obtém o salt de um usuário
        """
        try:
            con = Database.get_connection()
            cursor = con.cursor()
            cursor.execute(Queries.GET_USER_BY_USERNAME, (username,))
            user = cursor.fetchone()
            
            if user:
                salt = user[4]
                return True, "Salt encontrado", salt
            else:
                return False, "Usuário não encontrado", None
        except Exception as e:
            return False, f"Erro: {e}", None

    @staticmethod  
    def authenticate_user(username, password):
        """
        Autentica usuário - compara hashes Argon2
        """
        try:
            con = Database.get_connection()
            cursor = con.cursor(dictionary=True)
            cursor.execute(Queries.GET_USER_BY_USERNAME, (username,))
            user = cursor.fetchone()
            
            if not user:
                return False, "Usuário não encontrado", None
            
            stored_hash = user['password']
            stored_salt = user['salt']
            
            from argon2 import PasswordHasher
            ph = PasswordHasher()
            
            if ph.verify(stored_hash, password + stored_salt):
                user_id = user['id']
                cursor.execute(Queries.UPDATE_USER_STATUS, (True, None, user_id))
                con.commit()
                
                user_data = {
                    'user_id': user_id,
                    'username': user['username'],
                    'public_key': user['public_key'],
                }
                
                return True, "Login realizado", user_data
            else:
                return False, "Senha incorreta", None
        except Exception as e:
            return False, f"Erro: {e}", None  
        
    @staticmethod
    def get_user_public_key(user_id):
        """
        Obtém a chave pública de um usuário
        Retorna: chave pública ou None
        """
        try:
            con = Database.get_connection()
            cursor = con.cursor(dictionary=True)
            
            cursor.execute(Queries.GET_USER_BY_ID, (user_id,))
            user = cursor.fetchone()
            
            return user['public_key'] if user else None
            
        except mysql.connector.Error as e:
            logger.error(f"Erro ao buscar chave pública: {e}")
            return None
    
    @staticmethod
    def logout_user(user_id):
        """
        Faz logout do usuário (atualiza status para offline)
        Retorna: (success, message)
        """
        try:
            con = Database.get_connection()
            cursor = con.cursor()
            cursor.execute(Queries.UPDATE_USER_STATUS, 
                         (False, datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'), user_id))
            con.commit()
            
            logger.info(f"Logout realizado: user_id {user_id}")
            return True, "Logout realizado com sucesso"
            
        except mysql.connector.Error as e:
            error_message = f"Erro no logout: {e}"
            logger.error(error_message)
            return False, error_message
    
    @staticmethod
    def get_user_id(username):
        """
        Obtém o ID do usuário pelo username
        Retorna: user_id ou None se não encontrado
        """
        try:
            con = Database.get_connection()
            cursor = con.cursor()
            
            cursor.execute(Queries.GET_USER_ID, (username,))
            user = cursor.fetchone()
            
            return user[0] if user else None
            
        except mysql.connector.Error as e:
            logger.error(f"Erro ao buscar user_id: {e}")
            return None