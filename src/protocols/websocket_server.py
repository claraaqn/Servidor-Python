import asyncio
import websockets
import json
import logging
from src.config.config import Config
from src.database.database import Database
from src.database.queries import Queries
from src.handlers.auth_handler import AuthHandler
from src.handlers.message_handler import MessageHandler
from src.handlers.utils import create_response, DateTimeEncoder
import traceback

logger = logging.getLogger(__name__)

# Dicionário para manter conexões WebSocket ativas
websocket_connections = {}

class WebSocketServer:
    def __init__(self):
        self.host = Config.WS_HOST
        self.port = Config.WS_PORT
        self.server = None
        self._loop = None
    
    async def handle_websocket(self, websocket):
        """Lida com conexões WebSocket"""
        path = websocket.request.path
        logger.info(f"Caminho da conexão: {path}")
        user_id = None
        username = None
        
        try:
            logger.info(f"🔗 Nova conexão WebSocket de {websocket.remote_address}")
            
            async for message in websocket:
                try:
                    data = json.loads(message)
                    action = data.get('action')
                    
                    logger.info(f"📥 Mensagem WebSocket recebida: {action} de {username or 'unknown'}")
                    
                    response = await self.process_message(
                        data, action, websocket, user_id, username
                    )
                    
                    # Atualiza user_id se login for bem-sucedido
                    if action == 'login' and response.get('success'):
                        user_id = response.get('data', {}).get('user_id')
                        username = data.get('username')
                        if user_id:
                            websocket_connections[user_id] = websocket
                            logger.info(f"👤 Usuário {username} (ID: {user_id}) conectado via WebSocket")
                            
                            # Broadcast status online
                            await self.broadcast_user_status(user_id, username, True)
                    
                    # Envia resposta para o cliente
                    await websocket.send(json.dumps(response, cls=DateTimeEncoder))
                    
                    # Processa ações que requerem notificação em tempo real
                    if action == 'send_message' and response.get('success'):
                        await self.handle_real_time_message(data, user_id, username)
                    
                    elif action in ['typing_start', 'typing_stop'] and user_id:
                        is_typing = action == 'typing_start'
                        await self.handle_typing_indicator(data, user_id, username, is_typing)
                        
                except json.JSONDecodeError as e:
                    logger.error(f"JSON inválido: {e}")
                    error_response = create_response(False, "JSON inválido")
                    await websocket.send(json.dumps(error_response))
                except Exception as e:
                    logger.error(f"Erro ao processar mensagem WebSocket: {e}")
                    logger.error(f"Traceback: {traceback.format_exc()}")
                    error_response = create_response(False, f"Erro interno: {str(e)}")
                    await websocket.send(json.dumps(error_response))
                    
        except websockets.exceptions.ConnectionClosed as e:
            logger.info(f"🔗 Conexão WebSocket fechada: {username or 'Unknown'} - {e}")
        except Exception as e:
            logger.error(f"Erro inesperado na conexão WebSocket: {e}")
            logger.error(f"Traceback: {traceback.format_exc()}")
        finally:
            # Remove da lista de conexões ativas e faz logout
            if user_id:
                if user_id in websocket_connections:
                    del websocket_connections[user_id]
                    logger.info(f"👤 Usuário {username} (ID: {user_id}) removido das conexões ativas")
                
                # Atualiza status para offline e broadcast
                try:
                    if username:
                        await self.broadcast_user_status(user_id, username, False)
                    
                    success, message = AuthHandler.logout_user(user_id)
                    if success:
                        logger.info(f"👤 Logout automático realizado para {username} (ID: {user_id})")
                    else:
                        logger.warning(f"⚠️ Erro no logout automático para {username}: {message}")
                except Exception as e:
                    logger.error(f"Erro ao fazer logout automático: {e}")
    
    async def process_message(self, data, action, websocket, user_id, username):
        """Processa mensagens WebSocket"""
        try:
            if action == 'register':
                return await self.handle_register(data)
            
            elif action == 'login':
                return await self.handle_login(data, user_id)
            
            elif action == 'logout':
                return await self.handle_logout(data, user_id, username)
            
            elif action == 'send_message':
                return await self.handle_send_message(data, user_id, username)
            
            elif action == 'get_contacts':
                return await self.handle_get_contacts(user_id)
            
            elif action == 'get_undelivered_messages':
                return await self.handle_get_undelivered_messages(user_id)
            
            elif action == 'get_conversation_history':
                return await self.handle_get_conversation_history(data, user_id)
            
            elif action == 'send_friend_request':
                return await self.handle_send_friend_request(data, user_id)
            
            elif action == 'get_friend_requests':
                return await self.handle_get_friend_requests(user_id)
            
            elif action == 'respond_friend_request':
                return await self.handle_respond_friend_request(data, user_id)
            
            elif action == 'get_friends_list':
                return await self.handle_get_friends_list(user_id)
            
            elif action in ['typing_start', 'typing_stop']:
                return await self.handle_typing(data, user_id, action)
            
            else:
                return create_response(False, f"Ação '{action}' não reconhecida")
                
        except Exception as e:
            logger.error(f"Erro no process_message para ação {action}: {e}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            return create_response(False, f"Erro interno: {str(e)}")
    
    async def handle_register(self, data):
        """Processa registro de usuário"""
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return create_response(False, "Username e password são obrigatórios")
        
        success, message, user_id = AuthHandler.register_user(username, password)
        return create_response(success, message, {'user_id': user_id} if success else None)
    
    async def handle_login(self, data, current_user_id):
        """Processa login de usuário"""
        if current_user_id:
            return create_response(False, "Usuário já está autenticado")
        
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return create_response(False, "Username e password são obrigatórios")
        
        success, message, user_id = AuthHandler.authenticate_user(username, password)
        
        if success:
            # Obtém mensagens não entregues
            undelivered_messages = MessageHandler.get_undelivered_messages(user_id)
            # Obtém lista de contatos
            contacts = MessageHandler.get_contacts(user_id)
            
            connection = Database.get_connection()
            cursor = connection.cursor()
            cursor.execute(Queries.UPDATE_USER_STATUS, (True, None, user_id))
            connection.commit()
            
            response_data = {
                'user_id': user_id,
                'username': username,
                'undelivered_messages': undelivered_messages,
                'contacts': contacts
            }
            return create_response(True, message, response_data)
        else:
            return create_response(False, message)
    
    async def handle_logout(self, data, user_id, username):
        """Processa logout de usuário"""
        if not user_id:
            return create_response(False, "Usuário não autenticado")
        
        success, message = AuthHandler.logout_user(user_id)
        if success:
            # Broadcast status offline
            await self.broadcast_user_status(user_id, username, False)
        return create_response(success, message)
    
    async def handle_send_message(self, data, user_id, username):
        """Processa envio de mensagem"""
        if not user_id:
            return create_response(False, "Usuário não autenticado")
        
        receiver_username = data.get('receiver_username')
        content = data.get('content')
        
        if not receiver_username or not content:
            return create_response(False, "Receiver username e content são obrigatórios")
        
        success, message, message_id = MessageHandler.send_message(user_id, receiver_username, content)
        return create_response(success, message, {'message_id': message_id} if success else None)
    
    async def handle_get_contacts(self, user_id):
        """Obtém lista de contatos"""
        if not user_id:
            return create_response(False, "Usuário não autenticado")
        
        contacts = MessageHandler.get_contacts(user_id)
        return create_response(True, "Lista de contatos", contacts)
    
    async def handle_get_undelivered_messages(self, user_id):
        """Obtém mensagens não entregues"""
        if not user_id:
            return create_response(False, "Usuário não autenticado")
        
        messages = MessageHandler.get_undelivered_messages(user_id)
        return create_response(True, "Mensagens não entregues", messages)
    
    async def handle_get_conversation_history(self, data, user_id):
        """Obtém histórico de conversa"""
        if not user_id:
            return create_response(False, "Usuário não autenticado")
        
        other_user_id = data.get('other_user_id')
        limit = data.get('limit', 50)
        
        if not other_user_id:
            return create_response(False, "other_user_id é obrigatório")
        
        messages = MessageHandler.get_conversation_history(user_id, other_user_id, limit)
        return create_response(True, "Histórico de conversa", messages)
    
    async def handle_send_friend_request(self, data, user_id):
        """Envia solicitação de amizade"""
        if not user_id:
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
    
    async def handle_get_friend_requests(self, user_id):
        """Obtém solicitações de amizade"""
        if not user_id:
            return create_response(False, "Usuário não autenticado")
        
        requests = MessageHandler.get_friend_requests(user_id)
        
        return {
            'action': 'get_friend_requests_response',
            'success': True,
            'message': "Solicitações de amizade",
            'data': requests
        }
    
    async def handle_respond_friend_request(self, data, user_id):
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
    
    async def handle_get_friends_list(self, user_id):
        """Obtém lista de amigos"""
        if not user_id:
            return create_response(False, "Usuário não autenticado")
        
        friends = MessageHandler.get_friends_list(user_id)
        
        return {
            'action': 'get_friends_list_response',
            'success': True,
            'message': "Lista de amigos",
            'data': friends
        }
    
    async def handle_real_time_message(self, data, sender_id, sender_username):
        """Lida com mensagens em tempo real para WebSocket"""
        if not sender_id or not sender_username:
            return
            
        try:
            receiver_username = data.get('receiver_username')
            content = data.get('content')
            
            if not receiver_username:
                return
            
            # Obtém ID do receptor
            receiver_id = AuthHandler.get_user_id(receiver_username)
            if not receiver_id:
                return
            
            # Se o receptor estiver online via WebSocket, envia a mensagem em tempo real
            if receiver_id in websocket_connections:
                receiver_ws = websocket_connections[receiver_id]
                
                real_time_msg = {
                    'action': 'new_message',
                    'sender_id': sender_id,
                    'sender_username': sender_username,
                    'content': content,
                    'timestamp': self.get_current_timestamp(),
                    'message_type': 'real_time'
                }
                
                await receiver_ws.send(json.dumps(real_time_msg, cls=DateTimeEncoder))
                logger.info(f"📨 Mensagem em tempo real enviada para {receiver_username}")
                
        except Exception as e:
            logger.error(f"Erro ao enviar mensagem em tempo real: {e}")
    
    async def handle_typing_indicator(self, data, user_id, username, is_typing):
        """Lida com indicadores de digitação em tempo real"""
        if not user_id or not username:
            return
            
        try:
            receiver_username = data.get('receiver_username')
            
            if not receiver_username:
                return
            
            # Obtém ID do receptor
            receiver_id = AuthHandler.get_user_id(receiver_username)
            if not receiver_id:
                return
            
            # Se o receptor estiver online via WebSocket, envia o indicador
            if receiver_id in websocket_connections:
                receiver_ws = websocket_connections[receiver_id]
                
                typing_msg = {
                    'action': 'user_typing',
                    'user_id': user_id,
                    'username': username,
                    'is_typing': is_typing,
                    'timestamp': self.get_current_timestamp()
                }
                
                await receiver_ws.send(json.dumps(typing_msg, cls=DateTimeEncoder))
                logger.debug(f"✍️ Indicador de digitação enviado para {receiver_username}")
                
        except Exception as e:
            logger.error(f"Erro ao enviar indicador de digitação: {e}")
    
    def get_current_timestamp(self):
        """Retorna timestamp atual no formato ISO"""
        from datetime import datetime
        return datetime.now().isoformat()
    
    async def broadcast_user_status(self, user_id, username, is_online):
        """Transmite mudança de status para todos os contatos online"""
        if not user_id or not username:
            return
            
        try:
            status_msg = {
                'action': 'user_status_change',
                'user_id': user_id,
                'username': username,
                'is_online': is_online,
                'timestamp': self.get_current_timestamp()
            }
            
            # Envia para todos os usuários online exceto o próprio usuário
            for conn_user_id, websocket in websocket_connections.items():
                if conn_user_id != user_id:
                    try:
                        await websocket.send(json.dumps(status_msg, cls=DateTimeEncoder))
                    except Exception as e:
                        logger.error(f"Erro ao broadcast status para {conn_user_id}: {e}")
                        # Remove conexão problemática
                        if conn_user_id in websocket_connections:
                            del websocket_connections[conn_user_id]
            
            logger.info(f"🌐 Status de {username} broadcasted: {'online' if is_online else 'offline'}")
            
        except Exception as e:
            logger.error(f"Erro no broadcast de status: {e}")
    
    def start(self):
        """Inicia o servidor WebSocket - versão simplificada e funcional"""
        async def main():
            try:
                async def websocket_handler(websocket, path):
                    await self.handle_websocket(websocket, path)
                    
                # Usa serve diretamente
                async with websockets.serve(
                    self.handle_websocket,
                    self.host, 
                    self.port,
                    ping_interval=20,
                    ping_timeout=10,
                    close_timeout=10
                ) as server:
                    self.server = server
                    logger.info(f"🌐 Servidor WebSocket ouvindo em {self.host}:{self.port}")
                    
                    await asyncio.Future()  # Run forever
                    
            except Exception as e:
                logger.error(f"Erro no servidor WebSocket: {e}")
                logger.error(f"Traceback: {traceback.format_exc()}")

        # Executa em um novo evento loop
        asyncio.run(main())
        
    def stop(self):
        """Para o servidor WebSocket"""
        if self.server:
            self.server.close()
        if self._loop:
            self._loop.stop()
        logger.info("🛑 Servidor WebSocket parado")