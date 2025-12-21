import base64
import hashlib
import hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
import logging

logger = logging.getLogger(__name__)

class ServerCryptoService:
    def __init__(self):
        self._session_keys = {}
    
    def set_session_keys(self, session_id, encryption_key, hmac_key):
        """Define as chaves de sessão para um cliente"""
        self._session_keys[session_id] = {
            'encryption_key': encryption_key,
            'hmac_key': hmac_key
        }
        
        logger.info(f"   ENC: {base64.b64encode(encryption_key).decode()}")
        logger.info(f"   HMAC: {base64.b64encode(hmac_key).decode()}")
        
    def remove_session_keys(self, session_id):
        """Remove chaves de sessão"""
        if session_id in self._session_keys:
            del self._session_keys[session_id]
    
    def encrypt_message(self, session_id, plaintext):
        """Criptografa uma mensagem para envio ao cliente"""
        if session_id not in self._session_keys:
            raise Exception("Chaves de sessão não definidas")
        
        try:
            session_keys = self._session_keys[session_id]
            encryption_key = session_keys['encryption_key']
            hmac_key = session_keys['hmac_key']

            iv = os.urandom(16)  # IV aleatório
            cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            
            # Padding PKCS7
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()
            
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            
            encrypted_data = iv + ciphertext
            
            message_hmac = self._compute_hmac(encrypted_data, hmac_key)
            
            # 4. Codificar em base64 para transmissão
            result = {
                'ciphertext': base64.b64encode(encrypted_data).decode('utf-8'),
                'hmac': base64.b64encode(message_hmac).decode('utf-8')
            }
            
            return result
            
        except Exception as e:
            logger.error(f"❌ Erro ao criptografar mensagem: {e}")
            raise
    
    def decrypt_message(self, session_id, encrypted_message):
        """Descriptografa uma mensagem recebida do cliente"""
        if session_id not in self._session_keys:
            raise Exception("Chaves de sessão não definidas")
        
        try:
            session_keys = self._session_keys[session_id]
            encryption_key = session_keys['encryption_key']
            hmac_key = session_keys['hmac_key']
                        
            ciphertext_b64 = encrypted_message['ciphertext']
            received_hmac_b64 = encrypted_message['hmac']
            
            # Decodificar
            encrypted_data = base64.b64decode(ciphertext_b64)
            received_hmac = base64.b64decode(received_hmac_b64)
            
            computed_hmac = hmac.new(
                hmac_key, 
                encrypted_data,  
                digestmod=hashlib.sha256
            ).digest()
            
            if not hmac.compare_digest(computed_hmac, received_hmac):
                raise Exception("HMAC interno inválido")
            
            iv = encrypted_data[:16] 
            ciphertext = encrypted_data[16:]
            
            #Descriptografar
            cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
            # 5. Remover padding PKCS7 manualmente
            pad_length = padded_plaintext[-1]
            if pad_length < 1 or pad_length > 16:
                raise Exception("Padding inválido")
            
            plaintext = padded_plaintext[:-pad_length]
            
            return plaintext.decode('utf-8')
            
        except Exception as e:
            logger.error(f"❌ Erro ao descriptografar mensagem: {e}")
            raise
    
    def _compute_hmac(self, data, key):
        """Calcula HMAC-SHA256"""
        return hmac.new(key, data, hashlib.sha256).digest()
    
    def _compare_hmac(self, hmac1, hmac2):
        """Compara dois HMACs de forma segura (time-constant)"""
        return hmac.compare_digest(hmac1, hmac2)
    
    def is_session_encrypted(self, session_id):
        """Verifica se uma sessão tem criptografia ativa"""
        return session_id in self._session_keys