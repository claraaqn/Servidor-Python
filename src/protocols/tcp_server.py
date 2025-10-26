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
            
            elif action == 'get_conversation_history':
                return self.handle_get_conversation_history(data)

            elif action == 'check_user_online_status':
                return self.handle_check_user_online_status(data)
            
            elif action == 'get_pending_messages':
                return self.handle_get_pending_messages(data)
            
            elif action == 'confirm_message_delivery':
                return self.handle_confirm_message_delivery(data)
            
            elif action == 'cleanup_delivered_messages':
                return self.handle_cleanup_delivered_messages(self, data)
            
            elif action == 'mark_conversation_delivered':
                return self.handle_mark_conversation_delivered(data)
            
            elif action == 'get_contacts':
                return self.handle_get_contacts(data)

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

#! mensagaens    
    def handle_send_message(self, data):
        """Handler simplificado - servidor decide online/offline"""
        if not self.authenticated:
            return create_response(False, "Usuário não autenticado")
            
        receiver_username = data.get('receiver_username')
        content = data.get('content')
        local_id = data.get('local_id')
        
        logger.info(f"📨 Mensagem de {self.username} para {receiver_username}")
        
        if not receiver_username or not content:
            return create_response(False, "Dados incompletos")
        
        receiver_id = AuthHandler.get_user_id(receiver_username)
        is_receiver_online = False
        
        if receiver_id:
            is_receiver_online = (receiver_id in websocket_connections or 
                                receiver_id in tcp_connections)
        
        if is_receiver_online:
            logger.info(f"✅ Destinatário online - entregando em tempo real SEM banco")
            
            success = self.deliver_realtime_message(data, self.user_id, self.username, receiver_id)
            
            if success:
                return {
                    "action": "send_message_response",
                    "success": True,
                    "message": "Mensagem entregue em tempo real",
                    "data": {
                        "message_id": None,  
                        "is_offline": False,
                        "local_id": local_id
                    }
                }
        
        logger.info(f"💾 Salvando mensagem no banco")
        success, message, message_id = MessageHandler.send_message(
            self.user_id, receiver_username, content
        )
        
        if success:
            return {
                "action": "send_message_response",
                "success": True,
                "message": "Mensagem salva no servidor",
                "data": {
                    "message_id": message_id,
                    "is_offline": True,
                    "local_id": local_id
                }
            }
        else:
            return create_response(False, message)
       
    def deliver_realtime_message(self, data, sender_id, sender_username, receiver_id):
        """Entrega mensagem em tempo real sem salvar no servidor"""
        try:
            import time
            message_id = int(time.time() * 1000)
            
            real_time_msg = {
                'action': 'new_message',
                'id': message_id,
                'sender_id': sender_id,
                'sender_username': sender_username,
                'receiver_id': receiver_id,
                'receiver_username': data.get('receiver_username'),
                'content': data.get('content'),
                'timestamp': datetime.datetime.now().isoformat(),
                'is_delivered': True,
                'message_type': 'real_time'
            }
            
            message_sent = False
                
            if receiver_id in tcp_connections:                
                try:
                    message_json = json.dumps(real_time_msg, cls=DateTimeEncoder) + "\n"
                    receiver_socket = tcp_connections[receiver_id]
                    receiver_socket.sendall(message_json.encode('utf-8'))
                    logger.info(f"✅ Mensagem entregue via TCP")
                    message_sent = True
                
                except Exception as e:
                    logger.error(f"❌ Erro TCP: {e}")
                    if receiver_id in tcp_connections:
                        del tcp_connections[receiver_id]
                        
            if message_sent and data.get('db_message_id'):
                db_message_id = data['db_message_id']
                success = MessageHandler.delete_message_after_delivery(db_message_id)
                if success:
                    logger.info(f"🗑️ Mensagem {db_message_id} excluída do banco após entrega")
                else:
                    logger.warning(f"⚠️ Não foi possível excluir mensagem {db_message_id} do banco")
            
            return message_sent
            
        except Exception as e:
            logger.error(f"💥 Erro ao entregar mensagem: {e}")
            return False  
    
    def handle_get_pending_messages(self, data):
        """Envia mensagens pendentes e marca para exclusão"""
        if not self.authenticated:
            return create_response(False, "Usuário não autenticado")

        try:
            pending_messages = MessageHandler.get_undelivered_messages(self.user_id)
            
            logger.info(f"📨 Encontradas {len(pending_messages)} mensagens pendentes para {self.username}")
            
            return {
                "action": "get_pending_messages_response",
                "success": True,
                "message": f"{len(pending_messages)} mensagens pendentes",
                "data": pending_messages
            }
            
        except Exception as e:
            logger.error(f"❌ Erro ao buscar mensagens pendentes: {e}")
            return create_response(False, f"Erro ao buscar mensagens pendentes: {e}")

    def handle_confirm_message_delivery(self, data):
        """Confirma recebimento e exclui mensagem do servidor"""
        if not self.authenticated:
            return create_response(False, "Usuário não autenticado")
        
        message_id = data.get('message_id')
        if not message_id:
            return create_response(False, "message_id é obrigatório")
        
        try:
            success = MessageHandler.mark_message_as_delivered(message_id)
        
            if success:
                logger.info(f"🗑️ Mensagem {message_id} excluída do servidor após entrega")
                return {
                    "action": "confirm_delivery_response",
                    "success": True,
                    "message": "Mensagem excluída do servidor"
                }
            else:
                return create_response(False, "Erro ao excluir mensagem")
        except Exception as e:
            logger.error(f"❌ Erro ao confirmar entrega: {e}")
            return create_response(False, f"Erro ao confirmar entrega: {e}")
   
    def handle_get_conversation_history(self, data):
        if not self.authenticated:
            return create_response(False, "Usuário não autenticado")
            
        other_username = data.get('other_username')
        limit = data.get('limit', 50)
        
        if not other_username:
            return create_response(False, "other_username é obrigatório")
        
        # 🟢 SIMPLIFICAÇÃO: Buscar todas sem filtros complexos
        messages = MessageHandler.get_conversation_history_by_username(
            self.user_id, other_username, limit
        )
        
        return {
            "action": "get_conversation_history_response",
            "success": True,
            "message": f"Histórico com {len(messages)} mensagens",
            "data": messages
        }

    def handle_cleanup_delivered_messages(self, data):
        if not self.authenticated:
            return create_response(False, "Usuário não autenticado")
        
        other_username = data.get('other_username')
        if not other_username:
            return create_response(False, "other_username é obrigatório")
        
        other_user_id = AuthHandler.get_user_id(other_username)
        if not other_user_id:
            return create_response(False, "Usuário não encontrado")
        
        count = MessageHandler.get_undelivered_count(self.user_id, other_user_id)
        
        return {
            "action": "cleanup_messages_response",
            "success": True,
            "message": f"{count} mensagens não entregues",
            "data": {"pending_count": count}
        }

    def handle_check_user_online_status(self, data):
        if not self.authenticated:
            return create_response(False, "Usuário não autenticado")
        
        username = data.get('username')
        if not username:
            return create_response(False, "Username é obrigatório")
        
        user_id = AuthHandler.get_user_id(username)
        is_online = False
        
        if user_id:
            is_online = (user_id in websocket_connections or 
                        user_id in tcp_connections)
        
        return {
            "action": "user_online_status_response",
            "success": True,
            "data": {
                "username": username,
                "is_online": is_online,
                "user_id": user_id
            }
        }
  
    def handle_get_contacts(self):
        if not self.authenticated:
            return create_response(False, "Usuário não autenticado")
        
        contacts = MessageHandler.get_contacts(self.user_id)
        return create_response(True, "Lista de contatos", contacts)
   
    @staticmethod
    def get_conversation_history_by_username(user_id, other_username, limit=50):
        """Busca histórico por username em vez de user_id"""
        try:
            other_user_id = AuthHandler.get_user_id(other_username)
            if not other_user_id:
                return []
                
            return MessageHandler.get_conversation_history(user_id, other_user_id, limit)
        except Exception as e:
            logger.error(f"Erro ao buscar histórico por username: {e}")
            return []
        
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