import asyncio
import datetime
import socket
import threading
import json
import logging
from src.config.config import Config
from src.database.database import Database
from src.database.queries import Queries
from src.handlers.auth_handler import AuthHandler
from src.handlers.message_handler import MessageHandler
from src.handlers.utils import create_response, DateTimeEncoder
from src.protocols.connections import tcp_connections, websocket_connections
from src.protocols.websocket_server import websocket_loop

logger = logging.getLogger(__name__)

class TCPClientHandler:
    def __init__(self, client_socket, address):
        self.client_socket = client_socket
        self.address = address
        self.user_id = None
        self.username = None
        self.authenticated = False
        self.running = True
        

#? processamento incial
    def handle_client(self):
        buffer = ""
        user_id = None
        username = None
        try:
            logger.info(f"🔌 Nova conexão TCP de {self.address}")

            while self.running:
                data = self.client_socket.recv(4096)
                if not data:
                    break

                buffer += data.decode('utf-8')

                while '\n' in buffer:
                    line, buffer = buffer.split('\n', 1)
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        data_json = json.loads(line)
                        action = data_json.get('action')
                        
                        response = self.process_message(line, user_id, username)
                        self.send_response(response)
                        
                        resp_data = json.loads(line)
                        
                        if resp_data.get('action') == 'login' and response.get('success'):
                            user_id = response.get('data', {}).get('user_id')
                            username = resp_data.get('username')
                            self.user_id = user_id
                            self.username = username
                            self.authenticated = True
                            tcp_connections[user_id] = self.client_socket
                            logger.info(f"👤 Usuário {username} (ID: {user_id}) autenticado via TCP")
                            
                        elif action in ['typing_start', 'typing_stop'] and user_id:
                            is_typing = action == 'typing_start'
                            self.handle_typing_indicator(data_json, user_id, username, is_typing)
                    
                    except json.JSONDecodeError:
                        error_response = create_response(False, "JSON inválido")
                        self.send_response(error_response)
                    except Exception as e:
                        logger.error(f"Erro ao processar mensagem: {e}")
                        error_response = create_response(False, f"Erro interno: {str(e)}")
                        self.send_response(error_response)

        except Exception as e:
            logger.error(f"Erro na conexão com {self.address}: {e}")
        finally:
            self.cleanup()

    def process_message(self, raw_message, user_id, username):
        """
        Processa mensagens recebidas do cliente TCP.
        O `raw_message` deve ser uma string JSON.
        """
        try:
            data = json.loads(raw_message)
            action = data.get('action')

            if action == 'register':
                return self.handle_register(data)

            elif action == 'login':
                return self.handle_login(data)

            elif action == 'logout':
                return self.handle_logout(data)

            elif action == 'send_message':
                return self.handle_send_message(data)

            elif action == 'get_contacts':
                return self.handle_get_contacts()

            elif action == 'get_undelivered_messages':
                return self.handle_get_undelivered_messages()

            elif action == 'get_conversation_history':
                return self.handle_get_conversation_history(data)

            elif action == 'send_friend_request':
                return self.handle_send_friend_request(data, user_id)

            elif action == 'get_friend_requests':
                return self.handle_get_friend_requests(user_id)

            elif action == 'respond_friend_request':
                return self.handle_respond_friend_request(data, user_id)

            elif action == 'get_friends_list':
                return self.handle_get_friends_list(user_id)

            elif action in ['typing_start', 'typing_stop']:
                is_typing = action == 'typing_start'
                self.handle_typing_indicator(data, user_id, username, is_typing)
                return create_response(True, "Indicador de digitação enviado")

            else:
                return create_response(False, f"Ação '{action}' não reconhecida")

        except json.JSONDecodeError:
            return create_response(False, "JSON inválido")
        except Exception as e:
            logger.error(f"Erro ao processar mensagem: {e}")
            return create_response(False, f"Erro interno: {str(e)}")

#? handlers iniciais
    def handle_register(self, data):
        username = data.get('username')
        password = data.get('password')
        
        success, message, user_id = AuthHandler.register_user(username, password)
        if success:
            return create_response(True, message, {'user_id': user_id})
        else:
            return create_response(False, message)
    
    def handle_login(self, data):
        username = data.get('username')
        password = data.get('password')
        
        success, message, user_id = AuthHandler.authenticate_user(username, password)
        if success:
            self.user_id = user_id
            self.username = username
            self.authenticated = True
            
            tcp_connections[user_id] = self.client_socket
            
            connection = Database.get_connection()
            cursor = connection.cursor()
            cursor.execute(Queries.UPDATE_USER_STATUS, (True, None, self.user_id))
            connection.commit()
            
            return {
                'action': 'login_response',
                'success': True,
                'message': message,
                'data': {'user_id': user_id}
            }
        else:
            return {
                'action': 'login_response',
                'success': False,
                'message': message
            }
    
    def handle_logout(self, data):
        """Handle user logout"""
        if not self.authenticated:
            return create_response(False, "Usuário não autenticado")
        
        success, message = AuthHandler.logout_user(self.user_id)
        if success:
            self.authenticated = False
            self.user_id = None
            self.username = None
        return create_response(success, message)    
    
    def cleanup(self):
        """Limpeza quando cliente desconecta"""
        if self.authenticated and self.user_id:
            # Atualiza status para offline
            try:
                from src.database.database import Database
                from src.database.queries import Queries
                
                if self.user_id in tcp_connections:
                    del tcp_connections[self.user_id]
                
                connection = Database.get_connection()
                cursor = connection.cursor()
                cursor.execute(Queries.UPDATE_USER_STATUS, (False, datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'), self.user_id))
                connection.commit()
            except Exception as e:
                logger.error(f"Erro ao atualizar status: {e}")
        
        self.client_socket.close()
        logger.info(f"🔌 Cliente {self.address} desconectado")    
    
#? amizade         
    def handle_send_friend_request(self, data, user_id):
        """Handle sending friend request"""
        if not self.authenticated:
            return create_response(False, "Usuário não autenticado")
        
        receiver_username = data.get('receiver_username')
        
        if not receiver_username:
            return create_response(False, "receiver_username é obrigatório")
        
        success, message = MessageHandler.send_friend_request(user_id, receiver_username)
        return {
            'action': 'send_friend_request_response',
            'success': success,
            'message': message
        }

    def handle_get_friend_requests(self, user_id):
        """Handle getting friend requests"""
        if not self.authenticated:
            return create_response(False, "Usuário não autenticado")
        
        requests = MessageHandler.get_friend_requests(user_id)
        
        return {
            'action': 'get_friend_requests_response',
            'success': True,
            'message': "Solicitações de amizade",
            'data': requests
        }
     
    def handle_respond_friend_request(self, data, user_id):
        # inicializa logo
        request_id = data.get('request_id')
        reply_status = data.get('response')  # 'accepted' or 'rejected'

        if not user_id:
            return create_response(False, "Usuário não autenticado")

        if not request_id or not reply_status:
            return create_response(False, "request_id e response são obrigatórios")

        try:
            success, message = MessageHandler.respond_friend_request(request_id, reply_status)
            return {
                'action': 'respond_friend_request_response',
                'success': success,
                'message': message
            }
        except Exception as e:
            # aqui não use reply_status, use só request_id ou str(e)
            return {
                'action': 'respond_friend_request_response',
                'success': False,
                'message': f"Erro ao processar solicitação: {e}"
            }

    def handle_get_friends_list(self, user_id):
        """Handle getting friends list"""
        if not self.authenticated:
            return create_response(False, "Usuário não autenticado")
        
        friends = MessageHandler.get_friends_list(user_id)
        
        return {
            'action': 'get_friends_list_response',
            'success': True,
            'message': "Lista de amigos",
            'data': friends
        }
    
#! mensagens
    def handle_send_message(self, data):
        if not self.authenticated:
            return create_response(False, "Usuário não autenticado")
        
        receiver_username = data.get('receiver_username')
        content = data.get('content')
        
        if not receiver_username or not content:
            return create_response(False, "Receiver username e content são obrigatórios")
        
        success, message, message_id = MessageHandler.send_message(self.user_id, receiver_username, content)
        self.handle_real_time_message_tcp(data, self.user_id, self.username)
        
        return {
            "action": "send_message_response",
            "success": success,
            "message": message,
            "data": {"message_id": message_id} if success else None
        }
    
    def handle_get_undelivered_messages(self):
        if not self.authenticated:
            return {
                "action": "get_undelivered_messages_response",
                "success": False,
                "message": "Usuário não autenticado"
            }

        messages = MessageHandler.get_undelivered_messages(self.user_id)
        return {
            "action": "get_undelivered_messages_response",
            "success": True,
            "message": "Mensagens não entregues",
            "data": messages
        }

    def handle_get_conversation_history(self, data):
        if not self.authenticated:
            return {
                "action": "get_conversation_history_response",
                "success": False,
                "message": "Usuário não autenticado"
            }
        
        other_user_id = data.get('other_user_id')
        limit = data.get('limit', 50)
        
        if not other_user_id:
            return {
                "action": "get_conversation_history_response",
                "success": False,
                "message": "other_user_id é obrigatório"
            }

        messages = MessageHandler.get_conversation_history(self.user_id, other_user_id, limit)
        return {
            "action": "get_conversation_history_response",
            "success": True,
            "message": "Histórico de conversa",
            "data": messages
        }
   
    def handle_get_contacts(self):
        if not self.authenticated:
            return create_response(False, "Usuário não autenticado")
        
        contacts = MessageHandler.get_contacts(self.user_id)
        return create_response(True, "Lista de contatos", contacts)
 
    def handle_real_time_message_tcp(self, data, sender_id, sender_username):
        """Lida com mensagens em tempo real para clientes TCP"""
        if not sender_id or not sender_username:
            return

        try:
            receiver_username = data.get('receiver_username')
            content = data.get('content')

            if not receiver_username:
                return

            receiver_id = AuthHandler.get_user_id(receiver_username)
            if not receiver_id:
                for uid, ws in websocket_connections.items():
                    if getattr(ws, "username", None) == receiver_username:
                        receiver_id = uid
                        break

            if not receiver_id:
                logger.warning(f"Destinatário {receiver_username} não encontrado em AuthHandler nem WS")
                return

            real_time_msg = {
                'action': 'new_message',
                'id': None,  # Será definido pelo cliente temporariamente
                'sender_id': sender_id,
                'sender_username': sender_username,
                'receiver_id': receiver_id,
                'receiver_username': receiver_username,
                'content': content,
                'timestamp': datetime.datetime.now().isoformat(),
                'is_delivered': True,
                'message_type': 'real_time'
            }
            logger.debug(f"WS connections: {list(websocket_connections.keys())}")
            logger.debug(f"Receiver {receiver_username} tem ID {receiver_id}")

            if receiver_id in websocket_connections and websocket_loop:
                receiver_ws = websocket_connections[receiver_id]
                asyncio.run_coroutine_threadsafe(
                    receiver_ws.send(json.dumps(real_time_msg, cls=DateTimeEncoder)),
                    websocket_loop
                )
                logger.info(f"📨 Mensagem em tempo real enviada para {receiver_username} via WebSocket")
                
            elif receiver_id in tcp_connections:                
                try:
                    message_json = json.dumps(real_time_msg, cls=DateTimeEncoder) + "\n"
                    receiver_socket = tcp_connections[receiver_id]
                    receiver_socket.sendall(message_json.encode('utf-8'))
                    logger.info(f"📨 Mensagem em tempo real enviada para {receiver_username} via TCP")
                
                except Exception as e:
                    logger.error(f"Erro ao enviar mensagem TCP para {receiver_username}: {e}")
                    
                    if receiver_id in tcp_connections:
                        del tcp_connections[receiver_id]
            else:
                logger.info(f"📨 Destinatário {receiver_username} offline. Mensagem será entregue quando online.")
            
        except Exception as e:
            logger.error(f"Erro ao enviar mensagem em tempo real via TCP: {e}")

#! digitação
    def handle_typing_indicator(self, data, user_id, username, is_typing):
        if not user_id or not username:
            return

        try:
            receiver_username = data.get('receiver_username')
            if not receiver_username:
                return

            receiver_id = AuthHandler.get_user_id(receiver_username)
            if not receiver_id:
                logger.warning(f"Destinatário {receiver_username} não encontrado")
                return
            
            receiver_id = int(receiver_id)

            typing_msg = {
                'action': 'user_typing',
                'user_id': user_id,
                'username': username,
                'is_typing': is_typing,
                'timestamp': datetime.datetime.utcnow().isoformat()
            }

            logger.debug(f"WS connections: {list(websocket_connections.keys())}")
            logger.debug(f"Receiver {receiver_username} tem ID {receiver_id}")
            
            if receiver_id in websocket_connections and websocket_loop:
                receiver_ws = websocket_connections[receiver_id]
                asyncio.run_coroutine_threadsafe(
                    receiver_ws.send(json.dumps(typing_msg, cls=DateTimeEncoder)),
                    websocket_loop
                )
                logger.debug(f"✍️ Indicador de digitação enviado (WebSocket) para {receiver_username}")

            elif receiver_id in tcp_connections:
                receiver_socket = tcp_connections[receiver_id]
                message_json = json.dumps(typing_msg) + "\n"
                receiver_socket.sendall(message_json.encode('utf-8'))
                logger.debug(f"✍️ Indicador de digitação enviado (TCP) para {receiver_username}")

        except Exception as e:
            logger.error(f"Erro ao enviar indicador de digitação via TCP: {e}")
    
#? respota ao cliente
    def send_response(self, response):
        """Envia resposta para o cliente"""
        try:
            response_json = json.dumps(response, cls=DateTimeEncoder) + '\n'
            self.client_socket.send(response_json.encode('utf-8'))
        except Exception as e:
            logger.error(f"Erro ao enviar resposta: {e}")


class TCPServer:
    def __init__(self):
        self.host = Config.TCP_HOST
        self.port = Config.TCP_PORT
        self.socket = None
        self.running = False
        self.client_threads = []
    
    def start(self):
        """Inicia o servidor TCP"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.host, self.port))
            self.socket.listen(5)
            self.running = True
            
            logger.info(f"🐍 Servidor TCP ouvindo em {self.host}:{self.port}")
            
            while self.running:
                try:
                    client_socket, address = self.socket.accept()
                    client_handler = TCPClientHandler(client_socket, address)
                    
                    client_thread = threading.Thread(
                        target=client_handler.handle_client, 
                        daemon=True
                    )
                    client_thread.start()
                    self.client_threads.append(client_thread)
                    
                except Exception as e:
                    if self.running:
                        logger.error(f"Erro ao aceitar conexão: {e}")
                    
        except Exception as e:
            logger.error(f"Erro no servidor TCP: {e}")
    
    def stop(self):
        """Para o servidor TCP"""
        self.running = False
        if self.socket:
            self.socket.close()
        logger.info("🛑 Servidor TCP parado")