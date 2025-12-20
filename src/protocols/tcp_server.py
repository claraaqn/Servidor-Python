import asyncio
import datetime
from datetime import datetime as dt
import socket
import threading
import json
import logging
from src.database.database import Database
from src.crypto.crypto_service import ServerCryptoService
from src.handlers.handshake_handler import HandshakeHandler
from src.config.config import Config
from src.handlers.auth_handler import AuthHandler
from src.handlers.message_handler import MessageHandler
from src.handlers.utils import create_response, DateTimeEncoder
from src.protocols.connections import tcp_connections, websocket_connections
from src.protocols.websocket_server import websocket_loop

logger = logging.getLogger(__name__)

class TCPClientHandler:
    def __init__(self, client_socket, address, clients_dict):
        self.client_socket = client_socket
        self.address = address
        self.user_id = None
        self.username = None
        self.authenticated = False
        self.authenticated_user = None
        self.running = True
        self.auth_handler = AuthHandler()
        self.handshake_handler = HandshakeHandler()
        self.crypto_service = ServerCryptoService()
        self.session_id = None
        self.encryption_enabled = False
        
        self.clients_dict = clients_dict     

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
                        
                        response = self.process_message(line, self.user_id, self.username)
                        self.send_response(response)
                        
                        resp_data = json.loads(response) if isinstance(response, str) else response
                        
                        if resp_data.get('action') == 'login' and response.get('success'):
                            user_data = response.get('data', {}).get('user_data', {})
                            user_id = user_data.get('user_id')
                            username = user_data.get('username')
                            self.user_id = user_id
                            self.username = username
                            self.authenticated = True
                            tcp_connections[user_id] = self.client_socket
                            self.clients_dict[self.user_id] = self
                            self.server.clients[user_id] = self.client_socket
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
        """
        try:
            data = json.loads(raw_message)
            action = data.get('action')
            
            if self.encryption_enabled and self._is_encrypted_message(data):
                return self._handle_encrypted_message(data)
            
            no_auth_actions = [
                'register', 'login', 'get_user_salt', 'handshake_init',
                'initiate_challenge', 'verify_challenge'
            ]
            
            if action == 'register':
                return self.handle_register(data)

            elif action == 'login':
                return self.handle_login(data)
            
            elif action == 'get_user_salt':
                return self.handle_get_user_salt(data)

            elif action == 'logout':
                return self.handle_logout(data)
            
            elif action == 'handshake_init':
                response = self.handshake_handler.handle_handshake_init(data)
                if response.get('success'):
                    self.session_id = response['data']['session_id']
                    self.encryption_enabled = True
                    print(f"Criptografia ativada para sessão: {self.session_id}")
                return response
            
            elif action == 'send_message':
                return self.handle_send_message(data)
        
            elif action == 'initiate_challenge':
                return self.handle_initiate_challenge(data)

            elif action == 'verify_challenge':
                return self.handle_verify_challenge(data)
            
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
                return self.handle_send_friend_request(data, self.user_id)

            elif action == 'get_friend_requests':
                return self.handle_get_friend_requests(self.user_id)

            elif action == 'respond_friend_request':
                return self.handle_respond_friend_request(data, self.user_id)
            
            elif action == "handshake_complete":
                return self.handle_handshake_complete(data, user_id)

            elif action == 'get_friends_list':
                return self.handle_get_friends_list(self.user_id)

            elif action in ['typing_start', 'typing_stop']:
                is_typing = action == 'typing_start'
                self.handle_typing_indicator(data, user_id, username, is_typing)
                return create_response(True, "Indicador de digitação enviado")
            
            auth_actions = [
                "auth_challenge", 
                "auth_response_and_challenge", 
                "auth_final_verification",
                "auth_complete"
            ]

            if action in auth_actions:
                target_id = data.get("target_id")
                if target_id:
                    data['sender_id'] = self.user_id 
                    # Envia para o amigo
                    sent = self.send_to_user(target_id, data) 
                    
                    if sent:
                        return create_response(True, "Sinal enviado ao destinatário")
                    else:
                        return create_response(False, "Usuário destino offline ou não encontrado")
                
                return create_response(False, "Target ID não fornecido")

            else:
                return create_response(False, f"Ação '{action}' não reconhecida")

        except json.JSONDecodeError:
            return create_response(False, "JSON inválido")
        except Exception as e:
            logger.error(f"Erro ao processar mensagem: {e}")
            return create_response(False, f"Erro interno: {str(e)}")

#! criptografia
    def _is_encrypted_message(self, data):
        """Verifica se a mensagem está criptografada"""
        return data.get('action') == 'encrypted_message' and 'ciphertext' in data and 'hmac' in data
    
    def _handle_encrypted_message(self, data):
        """Processa mensagem criptografada"""
        try:
            if not self.session_id:
                return create_response(False, "Sessão não estabelecida")
            
            crypto_service = self.handshake_handler.get_crypto_service()
            
            # Descriptografa a mensagem
            encrypted_payload = {
                'ciphertext': data['ciphertext'],
                'hmac': data['hmac']
            }
            
            decrypted_json = crypto_service.decrypt_message(self.session_id, encrypted_payload)
            decrypted_data = json.loads(decrypted_json)
            
            print(f"🔓 Mensagem descriptografada: {decrypted_data.get('action')}")
            
            # Processa a mensagem descriptografada
            return self.process_decrypted_message(decrypted_data)
            
        except Exception as e:
            logger.error(f"❌ Erro ao processar mensagem criptografada: {e}")
            return create_response(False, f"Erro de criptografia: {str(e)}")
    
    def process_decrypted_message(self, decrypted_data):
        """Processa mensagem já descriptografada"""
        action = decrypted_data.get('action')
        user_id = self.user_id
        username = self.username
        
        # Reprocessa as ações com os dados descriptografados
        if action == 'send_message':
            return self.handle_send_message(decrypted_data)
        
        elif action == 'get_conversation_history':
            return self.handle_get_conversation_history(decrypted_data)
        
        elif action == 'typing_start':
            is_typing = True
            self.handle_typing_indicator(decrypted_data, user_id, username, is_typing)
            return create_response(True, "Indicador de digitação enviado")
        
        elif action == 'typing_stop':
            is_typing = False
            self.handle_typing_indicator(decrypted_data, user_id, username, is_typing)
            return create_response(True, "Indicador de digitação enviado")
        
        # Adicione outras ações que devem ser criptografadas
        
        else:
            return create_response(False, f"Ação criptografada '{action}' não reconhecida")

    def handle_initiate_challenge(self, data):
        """Inicia desafio de autenticação"""
        try:
            username = data.get('username')
            if not username:
                return {
                    'success': False,
                    'message': "Username é obrigatório",
                    'action': 'initiate_challenge_response'
                }
            
            success, message, nonce = self.auth_handler.initiate_challenge(username)
            
            if success:
                return {
                    'success': True,
                    'message': message,
                    'action': 'initiate_challenge_response',  
                    'data': {'nonce': nonce}
                }
            else:
                return {
                    'success': False,
                    'message': message,
                    'action': 'initiate_challenge_response'
                }
                
        except Exception as e:
            logger.error(f"Erro no handle_initiate_challenge: {e}")
            return {
                'success': False,
                'message': f"Erro interno: {str(e)}",
                'action': 'initiate_challenge_response' 
            }

    def handle_verify_challenge(self, data):
        """Verifica resposta do desafio"""
        try:
            username = data.get('username')
            signature = data.get('signature')
            
            if not username or not signature:
                return {
                    'success': False,
                    'message': "Username e signature são obrigatórios",
                    'action': 'verify_challenge_response'
                }
            
            success, message, user_data = self.auth_handler.verify_challenge_response(
                username, signature, self)
            
            if success:
                # Atualizar informações do usuário no handler
                self.user_id = user_data['user_id']
                self.username = user_data['username']
                self.authenticated = True
                
                logger.info(f"Usuário {username} autenticado via desafio. user_id: {self.user_id}")
                
                self.clients_dict[self.user_id] = self
                
                return {
                    'success': True,
                    'message': message,
                    'action': 'verify_challenge_response',
                    'data': {'user_data': user_data}
                }
            else:
                return {
                    'success': False,
                    'message': message,
                    'action': 'verify_challenge_response'
                }
                    
        except Exception as e:
            logger.error(f"Erro no handle_verify_challenge: {e}")
            return {
                'success': False,
                'message': f"Erro interno: {str(e)}",
                'action': 'verify_challenge_response'  
        }

#? handlers iniciais
    def set_authenticated_user(self, user_id, username):
        """Define o usuário autenticado para esta conexão"""
        self.authenticated_user = {
            'user_id': user_id,
            'username': username,
            'authenticated_at': datetime.datetime.now()
        }
        self.user_id = user_id
        self.username = username
        logger.info(f"Sessão autenticada - User: {username}, ID: {user_id}")
    
    def is_authenticated(self):
        """Verifica se a conexão está autenticada"""
        return self.authenticated_user is not None
    
    def clear_authentication(self):
        """Limpa a autenticação"""
        self.authenticated_user = None
        self.user_id = None
        self.username = None   
        
    def handle_register(self, data):
        username = data.get('username')
        password = data.get('password')
        public_key = data.get('public_key')
        salt = data.get("salt")
        request_id = data.get('request_id')
        
        success, message, user_id = AuthHandler.register_user(username, password, public_key, salt)
        
        response_data = {
            'success': success,
            'message': message,
            'action': 'register_response', 
            'request_id': request_id,     
        }
        
        if success:
            response_data['data'] = {'user_id': user_id}
            return response_data
        else:
            return create_response(False, message)
    
    def handle_login(self, data):
        username = data.get('username')
        password = data.get('password')
        request_id = data.get('request_id')  
        
        success, message, user_data = AuthHandler.authenticate_user(username, password)
        
        response_data = {
            'success': success,
            'message': message,
            'action': 'login_response', 
            'request_id': request_id,  
        }
        
        if success:
            self.user_id = user_data['user_id']
            self.username = user_data['username']
            self.authenticated = True
            
            self.clients_dict[self.user_id] = self
            
            response_data['data'] = {'user_data': user_data} 
            
            logger.info(f"👤 Usuário {self.username} (ID: {self.user_id}) autenticado via TCP")
           
            return response_data
            
        else:
            return response_data

    def handle_get_user_salt(self, data):
        """
        Manipula a requisição para obter o salt de um usuário
        """
        username = data.get('username')
        request_id = data.get('request_id')
                
        success, message, salt = AuthHandler.get_user_salt(username)
        
        response_data = {
            'success': success,
            'message': message,
            'action': 'user_salt_response',
            'request_id': request_id,
        }
        
        if success:
            response_data['data'] = {'salt': salt}
        else:
            print(f"❌ SALT NÃO ENCONTRADO: {message}")
        
        return response_data
    
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
        if self.encryption_enabled and self.session_id:
            # Remove chaves de sessão
            self.handshake_handler.get_crypto_service().remove_session_keys(self.session_id)
            print(f"🔑 Chaves de sessão removidas: {self.session_id}")
        
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
        
        receiver_username = data.get('receiver_username')
        public_key_sender = data.get("dhe_public_sender")
                
        if not receiver_username:
            return create_response(False, "receiver_username é obrigatório")
        
        if not public_key_sender:
            return create_response(False, "Chave pública Diffie-Hellman é obrigatória")
        
        success, message = MessageHandler.send_friend_request(
            user_id, receiver_username, public_key_sender)

        return {
            'action': 'send_friend_request_response',
            'success': success,
            'message': message
        }

    def handle_get_friend_requests(self, user_id):
        """Handle getting friend requests"""
        if not self.is_authenticated():
            return {
                'success': False,
                'message': 'Usuário não autenticado',
                'action': 'get_friend_requests_response'
            }
        
        requests = MessageHandler.get_friend_requests(user_id)
        
        return {
            'action': 'get_friend_requests_response',
            'success': True,
            'message': "Solicitações de amizade",
            'data': requests
        }
     
    def handle_respond_friend_request(self, data, user_id):
        reciverId = data.get('reciverId')
        reply_status = data.get('response')
        dhe_public_receiver = data.get("dhe_public_reciver")

        if not user_id:
            return create_response(False, "Usuário não autenticado")

        if not reciverId or not reply_status:
            return create_response(False, "reciverId e response são obrigatórios")

        try:
            success, message = MessageHandler.respond_friend_request(
                reciverId, reply_status, dhe_public_receiver)
                        
            if success and reply_status == "accepted":
                sender_id = message["sender_id"]
                receiver_public_key = message["receiver_public_key"]
                receiver_id = message["receiver_id"]
                
                data = {
                    "action": "friend_request_accepted",
                    "receiver_public_key": receiver_public_key,
                    "receiver_id": receiver_id,
                    "sender_id": sender_id
                }
                
                self.send_to_user(sender_id, data)
                
            return {
                'action': 'respond_friend_request_response',
                'success': success,
                'message': "Solicitação aceita com sucesso"
            }
            
        except Exception as e:
            return {
                'action': 'respond_friend_request_response',
                'success': False,
                'message': f"Erro ao processar solicitação: {e}"
            }
            
    def send_to_user(self, user_id, message):
        """
        Envia mensagem para um usuário específico - VERSÃO SIMPLES
        """
        try:
            if user_id not in self.clients_dict:
                print(f"Usuário {user_id} não está online")
                return False
            
            target_client = self.clients_dict[user_id]
            
            message_json = json.dumps(message)
            full_message = message_json + '\n'
            target_client.client_socket.send(full_message.encode('utf-8'))
            
            
            print(f"Mensagem enviada para {user_id}: {message.get('action', 'no-action')}")
            return True
            
        except Exception as e:
            print(f"Erro ao enviar para {user_id}: {e}")
            if user_id in self.clients_dict:
                del self.clients_dict[user_id]
            return False
                
    def handle_handshake_complete(self, data, user_id):
        reciverId = data.get("reciverId")
        session_id = data.get("session_id")
        salt = data.get("salt")
        encryption_key = data.get("encryption_key")
        hmac_key = data.get("hmac_key")
        shared_secret = data.get("shared_secret")
        
        logger.info("HandShake entre clientes sendo realizado !!!!!!!")

        if not reciverId:
            return create_response(False, "reciverId é obrigatório")

        try:
            connection = Database.get_connection()
            cursor = connection.cursor()

            update_query = """
                UPDATE friend_requests
                SET 
                    session_id = %s,
                    session_key_encrypted = %s,
                    iv = %s,
                    handshake_data = %s,
                    shared_secret = %s,
                    handshake_status = 'completed',
                    updated_at = NOW()
                WHERE receiver_id = %s
            """
            
            params = (
                session_id,        
                encryption_key,    
                hmac_key,         
                salt,              
                shared_secret,     
                reciverId
            )
            cursor.execute(update_query, params)

            connection.commit()
            
            logger.info("HandShake finalizado !!!!!!!")
            
            response = {
                "reciverId": reciverId
            }

            return create_response(True, "Handshake Finalizado", response, "handshake_finalizado")

        except Exception as e:
            return create_response(False, f"Erro: {e}")

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
        """Envia resposta para o cliente, criptografando se necessário"""
        try:
            if (self.encryption_enabled and 
                self.session_id and 
                response.get('action') != 'handshake_response'):
                
                # Criptografa apenas mensagens que NÃO são handshake
                crypto_service = self.handshake_handler.get_crypto_service()
                response_json = json.dumps(response, cls=DateTimeEncoder)
                encrypted_response = crypto_service.encrypt_message(self.session_id, response_json)
                
                # Envia como mensagem criptografada
                final_response = {
                    'action': 'encrypted_message',
                    **encrypted_response
                }
                response_json = json.dumps(final_response, cls=DateTimeEncoder) + '\n'
            else:
                # Envia resposta normal (incluindo handshake_response)
                response_json = json.dumps(response, cls=DateTimeEncoder) + '\n'
            
            self.client_socket.send(response_json.encode('utf-8'))
            
        except Exception as e:
            logger.error(f"Erro ao enviar resposta: {e}")


clients_dict = {}

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
                    client_handler = TCPClientHandler(client_socket, address, clients_dict)
                    
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