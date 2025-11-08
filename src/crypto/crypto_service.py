import base64
import json
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
        self._session_keys = {}  # session_id -> {encryption_key, hmac_key}
    
    def set_session_keys(self, session_id, encryption_key, hmac_key):
        """Define as chaves de sessão para um cliente"""
        self._session_keys[session_id] = {
            'encryption_key': encryption_key,
            'hmac_key': hmac_key
        }
    
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
            
            # 1. Cifrar com AES-256
            aleatorio = os.urandom(16)  # IV aleatório
            cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(aleatorio), backend=default_backend())
            encryptor = cipher.encryptor()
            
            # Padding PKCS7
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()
            
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            
            # 2. Combinar IV + ciphertext
            encrypted_data = aleatorio + ciphertext
            
            # 3. Calcular HMAC
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
                        
            ciphertext_b64 = encrypted_message.get('ciphertext')
            received_hmac_b64 = encrypted_message.get('hmac')
            
            if not ciphertext_b64 or not received_hmac_b64:
                raise Exception("Mensagem criptografada incompleta")
            
            # Decodificar de base64
            encrypted_data = base64.b64decode(ciphertext_b64)
            received_hmac = base64.b64decode(received_hmac_b64)
            
            # 1. Verificar HMAC antes de descriptografar
            computed_hmac = self._compute_hmac(encrypted_data, hmac_key)
            if not self._compare_hmac(received_hmac, computed_hmac):
                raise Exception("HMAC inválido - mensagem corrompida ou adulterada")
                        
            # 2. Extrair IV e ciphertext
            iv = encrypted_data[:16]
            ciphertext = encrypted_data[16:]
            
            # 3. Descriptografar
            cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            # 4. Remover padding
            unpadder = padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
            
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