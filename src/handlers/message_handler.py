import mysql.connector
import logging
from datetime import datetime
from src.database.database import Database
from src.database.queries import Queries
from src.handlers.utils import serialize_data

logger = logging.getLogger(__name__)

class MessageHandler:
    @staticmethod
    def send_message(sender_id, receiver_username, content):
        """
        Envia uma mensagem de um usuário para outro
        Retorna: (success, message, message_id)
        """
        try:
            connection = Database.get_connection()
            cursor = connection.cursor()
            
            cursor.execute(Queries.GET_USER_ID, (receiver_username,))
            receiver_result = cursor.fetchone()
            
            if not receiver_result:
                return False, "Destinatário não encontrado", None
            
            receiver_id = receiver_result[0]
            
            cursor.execute(Queries.CHECK_USER_ONLINE, (receiver_id,))
            online_result = cursor.fetchone()
            is_online = online_result[0] if online_result else False

            delivered = is_online
            
            cursor.execute(
                "INSERT INTO messages (sender_id, receiver_id, content, timestamp, delivered) VALUES (%s, %s, %s, %s, %s)",
                (sender_id, receiver_id, content, datetime.now(), 0)  # %s em vez de ?
            )
            message_id = cursor.lastrowid
            
            connection.commit()
            
            logger.info(f"💬 Mensagem {message_id} enviada de {sender_id} para {receiver_username} (delivered: {delivered})")
            return True, "Mensagem enviada com sucesso", message_id
            
        except mysql.connector.Error as e:
            error_message = f"Erro ao enviar mensagem: {e}"
            logger.error(error_message)
            return False, error_message, None
        except Exception as e:
            error_message = f"Erro inesperado: {e}"
            logger.error(error_message)
            return False, error_message, None
    
    @staticmethod
    def get_contacts(user_id):
        """
        Obtém lista de contatos (todos os usuários) com status
        Retorna: lista de contatos
        """
        try:
            connection = Database.get_connection()
            cursor = connection.cursor(dictionary=True)
            
            cursor.execute(Queries.GET_ALL_CONTACTS, (user_id,))
            contacts = cursor.fetchall()
            
            return serialize_data(contacts)
            
        except mysql.connector.Error as e:
            logger.error(f"Erro ao obter contatos: {e}")
            return []
        except Exception as e:
            logger.error(f"Erro inesperado ao obter contatos: {e}")
            return []
    
    @staticmethod
    def get_undelivered_messages(user_id):
        """
        Obtém mensagens não entregues para um usuário (quando estava offline)
        Retorna: lista de mensagens não entregues
        """
        try:
            connection = Database.get_connection()
            cursor = connection.cursor(dictionary=True)
            
            cursor.execute("""
                SELECT id, sender_id, receiver_id, content, timestamp 
                FROM messages 
                WHERE receiver_id = %s AND delivered = 0
                ORDER BY timestamp ASC
            """, (user_id,))
           
            messages = []
            for row in cursor.fetchall():
                messages.append({
                'id': row['id'], 
                'sender_id': row['sender_id'],
                'receiver_id': row['receiver_id'],
                'content': row['content'],
                'timestamp': row['timestamp'].isoformat() if hasattr(row['timestamp'], 'isoformat') else str(row['timestamp'])
            })
        
            connection.close()
            return messages
            
        except mysql.connector.Error as e:
            logger.error(f"Erro ao obter mensagens não entregues: {e}")
            return []
        except Exception as e:
            logger.error(f"Erro inesperado ao obter mensagens não entregues: {e}")
            return []
    
    @staticmethod
    def get_conversation_history(user_id, other_user_id, limit=50):
        """
        Obtém histórico de conversa entre dois usuários
        Retorna: lista de mensagens
        """
        try:
            connection = Database.get_connection()
            cursor = connection.cursor(dictionary=True)
            
            cursor.execute(
                Queries.GET_CONVERSATION_HISTORY,
                (user_id, other_user_id, other_user_id, user_id, limit)
            )
            messages = cursor.fetchall()
            
            return serialize_data(messages)
            
        except mysql.connector.Error as e:
            logger.error(f"Erro ao obter histórico: {e}")
            return []
        except Exception as e:
            logger.error(f"Erro inesperado ao obter histórico: {e}")
            return []
    
    @staticmethod
    def send_friend_request(sender_id, receiver_username):
        """
        Envia uma solicitação de amizade
        Retorna: (success, message)
        """
        try:
            connection = Database.get_connection()
            cursor = connection.cursor()
            
            # Obtém ID do destinatário
            cursor.execute(Queries.GET_USER_ID, (receiver_username,))
            receiver_result = cursor.fetchone()
            
            if not receiver_result:
                return False, "Usuário não encontrado"
            
            receiver_id = receiver_result[0]
            
            # Verifica se é o mesmo usuário
            if sender_id == receiver_id:
                return False, "Não é possível enviar solicitação para si mesmo"
            
            # Verifica se já existe solicitação ou amizade
            cursor.execute(
                Queries.CHECK_EXISTING_FRIENDSHIP,
                (sender_id, receiver_id, receiver_id, sender_id)
            )
            existing = cursor.fetchone()
            
            if existing:
                status = existing[1]
                if status == 'pending':
                    return False, "Solicitação de amizade já enviada"
                elif status == 'accepted':
                    return False, "Vocês já são amigos"
                elif status == 'rejected':
                    return False, "Solicitação já foi rejeitada anteriormente"
            
            # Cria nova solicitação
            cursor.execute(
                Queries.CREATE_FRIEND_REQUEST,
                (sender_id, receiver_id)
            )
            
            connection.commit()
            return True, "Solicitação de amizade enviada com sucesso"
            
        except mysql.connector.Error as e:
            error_message = f"Erro ao enviar solicitação de amizade: {e}"
            logger.error(error_message)
            return False, error_message
        except Exception as e:
            error_message = f"Erro inesperado: {e}"
            logger.error(error_message)
            return False, error_message

    @staticmethod
    def get_friend_requests(user_id):
        """
        Obtém solicitações de amizade pendentes
        Retorna: lista de solicitações
        """
        try:
            connection = Database.get_connection()
            cursor = connection.cursor(dictionary=True)
            
            cursor.execute(Queries.GET_FRIEND_REQUESTS, (user_id,))
            requests = cursor.fetchall()
            
            return serialize_data(requests)
            
        except mysql.connector.Error as e:
            logger.error(f"Erro ao obter solicitações de amizade: {e}")
            return []
        except Exception as e:
            logger.error(f"Erro inesperado ao obter solicitações: {e}")
            return []

    @staticmethod
    def respond_friend_request(request_id, response):
        """
        Responde a uma solicitação de amizade (accept/reject)
        Retorna: (success, message)
        """
        try:
            if response not in ['accepted', 'rejected']:
                return False, "Resposta inválida. Use 'accepted' ou 'rejected'"
            
            connection = Database.get_connection()
            cursor = connection.cursor()
            
            # Verifica se a solicitação existe e pertence ao usuário
            cursor.execute(
                "SELECT id FROM friend_requests WHERE id = %s AND status = 'pending'",
                (request_id,)
            )
            if not cursor.fetchone():
                return False, "Solicitação não encontrada ou já respondida"
            
            cursor.execute(Queries.UPDATE_FRIEND_STATUS, (response, request_id))
            
            if cursor.rowcount == 0:
                return False, "Solicitação não encontrada"
            
            connection.commit()
            
            action = "aceita" if response == 'accepted' else "rejeitada"
            return True, f"Solicitação de amizade {action}"
            
        except mysql.connector.Error as e:
            error_message = f"Erro ao responder solicitação: {e}"
            logger.error(error_message)
            return False, error_message
        except Exception as e:
            error_message = f"Erro inesperado: {e}"
            logger.error(error_message)
            return False, error_message

    @staticmethod
    def get_friends_list(user_id):
        """
        Obtém lista de amigos
        Retorna: lista de amigos
        """
        try:
            connection = Database.get_connection()
            cursor = connection.cursor(dictionary=True)
            
            cursor.execute(Queries.GET_FRIENDS_LIST, (user_id, user_id))
            friends = cursor.fetchall()
            
            for friend in friends:
                friend['is_online'] = bool(friend['is_online'])
            
            return serialize_data(friends)
            
        except mysql.connector.Error as e:
            logger.error(f"Erro ao obter lista de amigos: {e}")
            return []
        except Exception as e:
            logger.error(f"Erro inesperado ao obter lista de amigos: {e}")
            return []
        
    @staticmethod
    def get_last_message_id(sender_id, receiver_id, content):
        """Busca o ID da última mensagem enviada para incluir no real_time_msg"""
        try:
            connection = Database.get_connection()
            cursor = connection.cursor(dictionary=True)
            
            cursor.execute("""
                SELECT id FROM messages 
                WHERE sender_id = %s AND receiver_id = %s 
                ORDER BY id DESC LIMIT 1
            """, (sender_id, receiver_id))
            
            result = cursor.fetchone()
            cursor.close()
            
            if result:
                logger.info(f"✅ ID da mensagem encontrado: {result['id']}")
                return result['id']
            else:
                logger.warning("⚠️ Nenhuma mensagem encontrada para obter ID")
                return None
            
        except Exception as e:
            logger.error(f"❌ Erro ao buscar ID da mensagem: {e}")
            return None

    @staticmethod
    def mark_message_as_delivered(message_id):
        """Marca mensagem como entregue no banco"""
        try:
            conn = Database.get_connection()
            cursor = conn.cursor()
            
            cursor.execute(
                "UPDATE messages SET delivered = 1 WHERE id = %s",
                (message_id,)
            )
            
            cursor.execute(
                "DELETE FROM messages WHERE id = %s AND delivered = 1",
                (message_id,)
            )
            
            deleted = cursor.rowcount > 0
            conn.commit()
            conn.close()
            
            if deleted:
                logger.info(f"🗑️ Mensagem {message_id} EXCLUÍDA do banco após entrega")
                return True
            else:
                logger.warning(f"⚠️ Mensagem {message_id} não foi excluída (não encontrada ou não entregue)")
                return False
            
        except Exception as e:
            logger.error(f"❌ Erro ao marcar mensagem {message_id} como entregue: {e}")
            return False
    
