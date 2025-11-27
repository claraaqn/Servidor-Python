import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import secrets
from src.crypto.crypto_service import ServerCryptoService
import logging

logger = logging.getLogger(__name__)

class HandshakeHandler:
    def __init__(self):
        self._session_keys = {}
        self.crypto_service = ServerCryptoService()
    
    def handle_handshake_init(self, data):
        """
        Handshake
        """
        try:
            client_public_key_b64 = data.get('dhe_public_key')
            salt_b64 = data.get('salt')
            request_id = data.get('request_id')
            
            # 1. Servidor gera par DHE 
            server_private_key = x25519.X25519PrivateKey.generate()
            server_public_key = server_private_key.public_key()
                        
            # 2. Decodifica chave pública do cliente
            client_public_key_bytes = base64.b64decode(client_public_key_b64)
            
            if len(client_public_key_bytes) != 32:
                raise ValueError(f"Chave Ed25519 deve ter 32 bytes, mas tem {len(client_public_key_bytes)}")
            
            client_public_key = x25519.X25519PublicKey.from_public_bytes(client_public_key_bytes)
            
            # 3. Calcula segredo compartilhado
            shared_secret = server_private_key.exchange(client_public_key)
            
            # 4. Deriva chaves de sessão com HKDF
            salt = base64.b64decode(salt_b64)
            
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=64,
                salt=salt,
                info=b'session_keys_v1',
                backend=default_backend()
            )
            
            key_material = hkdf.derive(shared_secret)
            encryption_key = key_material[:32]
            hmac_key = key_material[32:64]
            
            # 5. Armazena chaves de sessão
            session_id = self._generate_session_id()
            self._session_keys[session_id] = {
                'encryption_key': encryption_key,
                'hmac_key': hmac_key,
                'salt': salt_b64
            }
            
            # 6. Configura chaves no serviço de criptografia
            self.crypto_service.set_session_keys(session_id, encryption_key, hmac_key)
            
            # 7. Codifica chave pública do servidor
            server_pub_bytes = server_public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            server_pub_b64 = base64.b64encode(server_pub_bytes).decode()
            
            response_data = {
                'success': True,
                'message': 'Handshake realizado',
                'action': 'handshake_response',
                'request_id': request_id,
                'data': {
                    'server_public_key': server_pub_b64,
                    'session_id': session_id
                }
            }
            
            logger.info("HandShake OK")
                        
            return response_data
            
        except Exception as e:
            logger.error(f"❌ Erro detalhado no handshake: {e}")
            import traceback
            traceback.print_exc()
            
            return {
                'success': False,
                'message': f'Erro no handshake: {e}',
                'action': 'handshake_response',
                'request_id': request_id
            }
                  
    def _generate_session_id(self):
        return secrets.token_hex(16)
    
    def get_session_keys(self, session_id):
        return self._session_keys.get(session_id)
    
    def get_crypto_service(self):
        return self.crypto_service