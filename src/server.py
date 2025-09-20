import socket
import threading
import json
from src.config.config import Config
from src.database.database import Database
from src.handlers.auth_handler import AuthHandler
from src.utils.logger import setup_logger

logger = setup_logger()

class ChatServer:
    def __init__(self, host=None, port=None):
        # ⬇️ FORÇA PORTA 8080 SE NENHUMA FOR ESPECIFICADA
        self.host = host or 'localhost'
        self.port = port or 8080  # ⬅️ PORTA PADRÃO 8080
        self.server_socket = None
        self.running = False
        self.clients = {}  # Dicionário para armazenar clientes conectados
        
    def start_server(self):
        try:
            # Testa conexão com banco primeiro
            try:
                connection = Database.get_connection()
                if connection.is_connected():
                    logger.info("Conexão com banco de dados OK")
                connection.close()
            except Exception as e:
                logger.error(f"Erro no banco de dados: {e}")
                return
            
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            logger.info(f"Tentando iniciar servidor em {self.host}:{self.port}")
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            
            self.running = True
            logger.info(f"✅ Servidor iniciado com sucesso em {self.host}:{self.port}")
            logger.info("👂 Aguardando conexões...")
            
            while self.running:
                try:
                    client_socket, address = self.server_socket.accept()
                    logger.info(f"✅ Conexão recebida de {address}")
                    
                    # Processa cliente em thread separada
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, address),
                        daemon=True
                    )
                    client_thread.start()
                    
                except Exception as e:
                    if self.running:
                        logger.error(f"Erro ao aceitar conexão: {e}")
                        
        except Exception as e:
            logger.error(f"❌ Erro ao iniciar servidor: {e}")
            import traceback
            traceback.print_exc()
        finally:
            self.stop_server()
    
    def handle_client(self, client_socket, address):
        """Maneja a comunicação com um cliente"""
        try:
            while self.running:
                data = client_socket.recv(1024).decode('utf-8').strip()
                if not data:
                    break
                
                logger.info(f"📩 Dados recebidos de {address}: {data}")
                
                try:
                    message = json.loads(data)
                    self.process_message(client_socket, message, address)
                    
                except json.JSONDecodeError:
                    error_response = json.dumps({
                        'type': 'error',
                        'message': 'JSON inválido',
                        'success': False
                    })
                    client_socket.send((error_response + '\n').encode('utf-8'))
                    
        except Exception as e:
            logger.error(f"Erro com cliente {address}: {e}")
        finally:
            client_socket.close()
            logger.info(f"❌ Conexão fechada: {address}")
    
    def process_message(self, client_socket, message, address):
        """Processa mensagens JSON dos clientes"""
        message_type = message.get('type')
        
        if message_type == 'register':
            self.handle_register(client_socket, message, address)
        elif message_type == 'login':
            self.handle_login(client_socket, message, address)
        else:
            error_response = json.dumps({
                'type': 'error',
                'message': 'Tipo de mensagem desconhecido',
                'success': False
            })
            client_socket.send((error_response + '\n').encode('utf-8'))
    
    def handle_register(self, client_socket, message, address):
        """Processa registro de usuário"""
        username = message.get('username')
        password = message.get('password')
        
        if not username or not password:
            response = {
                'type': 'register_response',
                'success': False,
                'message': 'Username e password são obrigatórios'
            }
        else:
            success, message_text, user_id = AuthHandler.register_user(username, password)
            response = {
                'type': 'register_response',
                'success': success,
                'message': message_text,
                'user_id': user_id
            }
        
        # Envia resposta
        json_response = json.dumps(response) + '\n'
        client_socket.send(json_response.encode('utf-8'))
        logger.info(f"📤 Resposta enviada para {address}: {json_response.strip()}")
    
    def handle_login(self, client_socket, message, address):
        """Processa login de usuário"""
        username = message.get('username')
        password = message.get('password')
        
        success, message_text, user_id = AuthHandler.authenticate_user(username, password)
        response = {
            'type': 'login_response',
            'success': success,
            'message': message_text,
            'user_id': user_id
        }
        
        # Envia resposta
        json_response = json.dumps(response) + '\n'
        client_socket.send(json_response.encode('utf-8'))
        logger.info(f"📤 Resposta login para {address}: {json_response.strip()}")
    
    def stop_server(self):
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        Database.close_connection()
        logger.info("🛑 Servidor parado")

if __name__ == "__main__":
    server = ChatServer('localhost', 8080)  # ⬅️ FORÇA PORTA 8080
    server.start_server()