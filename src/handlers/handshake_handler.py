import os
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import secrets

class HandshakeHandler:
    def __init__(self):
        self._session_keys = {}
    
    def handle_handshake_init(self, data):
        """
        Handshake com Ed25519 (32 bytes)
        """
        try:
            client_public_key_b64 = data.get('dhe_public_key')
            salt_b64 = data.get('salt')
            request_id = data.get('request_id')
            
            print(f"🔑 Handshake recebido")
            print(f"📏 Tamanho chave cliente: {len(client_public_key_b64)} chars base64")
            print(f"🧂 Salt: {salt_b64}")
            
            # 1. Servidor gera par DHE efêmero com Ed25519
            server_private_key = ed25519.Ed25519PrivateKey.generate()
            server_public_key = server_private_key.public_key()
            
            print("📐 Curva usada no servidor: Ed25519")
            
            # 2. Decodifica chave pública do cliente (deve ser 32 bytes - Ed25519)
            client_public_key_bytes = base64.b64decode(client_public_key_b64)
            print(f"📏 Bytes chave cliente: {len(client_public_key_bytes)} bytes")
            
            # Verifica se é Ed25519 (32 bytes)
            if len(client_public_key_bytes) != 32:
                raise ValueError(f"Chave Ed25519 deve ter 32 bytes, mas tem {len(client_public_key_bytes)}")
            
            # Cria chave pública Ed25519 a partir dos bytes
            client_public_key = ed25519.Ed25519PublicKey.from_public_bytes(client_public_key_bytes)
            print("✅ Chave cliente Ed25519 válida")
            
            # 3. Calcula "segredo compartilhado" simplificado
            # Em produção real, use X25519 para ECDH com Ed25519
            print("🔐 Calculando segredo compartilhado...")
            
            # Para demonstração: combina chaves e faz hash
            combined = client_public_key_bytes + base64.b64decode(salt_b64)
            shared_secret = hashes.Hash(hashes.SHA256(), backend=default_backend())
            shared_secret.update(combined)
            shared_secret_bytes = shared_secret.finalize()[:32]
            
            print(f"📏 Segredo compartilhado: {len(shared_secret_bytes)} bytes")
            
            # 4. Deriva chaves de sessão com HKDF
            salt = base64.b64decode(salt_b64) if salt_b64 else b""
            
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=64,
                salt=salt,
                info=b'session_keys_v1',
                backend=default_backend()
            )
            
            key_material = hkdf.derive(shared_secret_bytes)
            encryption_key = key_material[:32]
            hmac_key = key_material[32:64]
            
            # 5. Armazena chaves de sessão
            session_id = self._generate_session_id()
            self._session_keys[session_id] = {
                'encryption_key': encryption_key,
                'hmac_key': hmac_key,
                'salt': salt_b64
            }
            
            # 6. Codifica chave pública do servidor (Ed25519 - 32 bytes)
            server_pub_bytes = server_public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            server_pub_b64 = base64.b64encode(server_pub_bytes).decode()
            
            response_data = {
                'success': True,
                'message': 'Handshake Ed25519 realizado',
                'action': 'handshake_response',
                'request_id': request_id,
                'data': {
                    'server_public_key': server_pub_b64,
                    'session_id': session_id
                }
            }
            
            print("✅ Handshake Ed25519 realizado com sucesso!")
            return response_data
            
        except Exception as e:
            print(f"❌ Erro detalhado no handshake: {e}")
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