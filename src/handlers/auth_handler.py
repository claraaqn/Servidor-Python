import logging
import datetime
import os
import traceback
import mysql.connector
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature
import secrets
import base64
from src.database.database import Database
from src.database.queries import Queries

logger = logging.getLogger(__name__)

class AuthHandler:
    
    _ph = PasswordHasher()
    
    def __init__(self):
        self._pending_challenges = {}
    
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
            
            cursor.execute("SELECT public_key FROM users WHERE id = %s", (user_id,))
            saved_public_key = cursor.fetchone()[0]

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

    def initiate_challenge(self, username):
        """
        Inicia desafio de autenticação - gera nonce aleatório
        """
        try:
            con = Database.get_connection()
            cursor = con.cursor(dictionary=True)
            cursor.execute(Queries.GET_USER_BY_USERNAME, (username,))
            user = cursor.fetchone()
            
            if not user:
                return False, "Usuário não encontrado", None
            
            nonce = secrets.token_bytes(32)
            nonce_b64 = base64.b64encode(nonce).decode('utf-8')
            
            self._pending_challenges[username] = {
                'nonce': nonce,
                'timestamp': datetime.datetime.now()
            }
            
            self._clean_old_challenges()
            
            logger.info(f"Desafio gerado para {username}: {nonce_b64}")
            
            return True, "Desafio gerado", nonce_b64
            
        except Exception as e:
            logger.error(f"Erro ao gerar desafio: {e}")
            return False, f"Erro: {e}", None
    
    def verify_challenge_response(self, username, signature_b64, client_handler=None):
        """
        Verifica a resposta do desafio (assinatura do nonce)
        """
        try:
            if username not in self._pending_challenges:
                logger.error(f"Desafio não encontrado para usuário: {username}")
                return False, "Desafio não encontrado ou expirado", None
            
            challenge = self._pending_challenges[username]
            nonce = challenge['nonce']
            timestamp = challenge['timestamp']
            
            if (datetime.datetime.now() - timestamp).total_seconds() > 300:
                del self._pending_challenges[username]
                return False, "Desafio expirado", None
            
            public_key = self.get_user_public_key_by_username(username)
            if not public_key:
                logger.error(f"Chave pública não encontrada para usuário: {username}")
                return False, "Chave pública não encontrada", None
            
            try:
                public_key_bytes = base64.b64decode(public_key)
                signature = base64.b64decode(signature_b64)
                
                public_key_obj = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
                
                public_key_obj.verify(signature, nonce)
                
                user_data = self._authenticate_user_after_challenge(username)
                
                if client_handler and user_data:
                    client_handler.set_authenticated_user(
                        user_data['user_id'], 
                        user_data['username']
                    )
                
                del self._pending_challenges[username]
                
                logger.info(f"Autenticação por desafio bem-sucedida para {username}")
                return True, "Autenticação bem-sucedida", user_data
                
            except InvalidSignature as e:
                logger.warning(f"Assinatura inválida para usuário {username}: {e}")
                
                self._debug_signature_verification(nonce, signature, public_key_bytes)
                
                return False, "Assinatura inválida", None
            except Exception as e:
                logger.error(f"Erro na verificação da assinatura: {e}")
                logger.error(traceback.format_exc())
                return False, f"Erro na verificação: {e}", None
                    
        except Exception as e:
            logger.error(f"Erro ao verificar desafio: {e}")
            logger.error(traceback.format_exc())
            return False, f"Erro: {e}", None

    def _debug_signature_verification(self, nonce, signature, public_key_bytes):
        """Método de debug para verificação de assinatura"""
        try:
            
            if len(signature) != 64:
                logger.error(f" Tamanho da assinatura incorreto: esperado 64, obtido {len(signature)}")
            
            if len(public_key_bytes) != 32:
                logger.error(f" Tamanho da chave pública incorreto: esperado 32, obtido {len(public_key_bytes)}")
                
        except Exception as e:
            logger.error(f"Erro no debug: {e}")
    
    def _authenticate_user_after_challenge(self, username):
        """
        Autentica usuário após desafio bem-sucedido
        """
        try:
            con = Database.get_connection()
            cursor = con.cursor(dictionary=True)
            cursor.execute(Queries.GET_USER_BY_USERNAME, (username,))
            user = cursor.fetchone()
            
            if not user:
                return None
            
            user_id = user['id']
            
            cursor.execute(Queries.UPDATE_USER_STATUS, (True, None, user_id))
            con.commit()
            
            user_data = {
                'user_id': user_id,
                'username': user['username'],
                'public_key': user['public_key'],
            }
            
            return user_data
            
        except Exception as e:
            logger.error(f"Erro na autenticação pós-desafio: {e}")
            return None
    
    def _clean_old_challenges(self):
        """Limpa desafios antigos"""
        now = datetime.datetime.now()
        expired_usernames = []
        
        for username, challenge in self._pending_challenges.items():
            if (now - challenge['timestamp']).total_seconds() > 300:  # 5 minutos
                expired_usernames.append(username)
        
        for username in expired_usernames:
            del self._pending_challenges[username]
    
    @staticmethod
    def get_user_public_key_by_username(username):
        """
        Obtém a chave pública de um usuário pelo username
        """
        try:
            con = Database.get_connection()
            cursor = con.cursor(dictionary=True)
            
            cursor.execute(Queries.GET_USER_BY_USERNAME, (username,))
            user = cursor.fetchone()
            
            return user['public_key'] if user else None
            
        except Exception as e:
            logger.error(f"Erro ao buscar chave pública: {e}")
            return None

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
    def authenticate_new_device(username, password, new_public_key):
        try:
            con = Database.get_connection()
            cursor = con.cursor(dictionary=True)
            
            cursor.execute("SELECT id, username, password, salt FROM users WHERE username = %s", (username,))
            user = cursor.fetchone()
            
            if not user:
                return False, "Usuário não encontrado", None
            
            stored_hash = user['password']
            stored_salt = user['salt']
            
            from argon2 import PasswordHasher
            ph = PasswordHasher()
            
            try:
                ph.verify(stored_hash, password + stored_salt)
                
                user_id = user['id']
                cursor.execute("UPDATE users SET public_key = %s WHERE id = %s", (new_public_key, user_id))
                con.commit()
                
                return True, "Sucesso", user
            except Exception as e:
                logger.error(f"Erro: {e}")
        except Exception as e:
            logger.error(f"Erro: {e}")
        
    @staticmethod
    def get_online_friends_ids(user_id):
        """
        Retorna uma lista de IDs de amigos que estão atualmente online.
        """
        try:
            con = Database.get_connection()
            cursor = con.cursor()
            
            query = """
                SELECT u.id 
                FROM friendships f
                JOIN users u ON (f.user_id_1 = u.id OR f.user_id_2 = u.id)
                WHERE (f.user_id_1 = %s OR f.user_id_2 = %s)
                AND u.id != %s
                AND u.is_online = TRUE
            """
            cursor.execute(query, (user_id, user_id, user_id))
            
            friends = [row[0] for row in cursor.fetchall()]
            return friends
        except Exception as e:
            logger.error(f"Erro ao buscar IDs de amigos online: {e}")
            return []
        
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