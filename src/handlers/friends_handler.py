import mysql.connector
from src.database.database import Database
from src.database.queries import Queries

class FriendsHandler:
    @staticmethod
    def get_friends(user_id):
        """Obtém a lista de amigos do usuário"""
        try:
            connection = Database.get_connection()
            cursor = connection.cursor(dictionary=True)
            
            cursor.execute(Queries.GET_FRIENDS, (user_id, user_id, user_id))
            friends = cursor.fetchall()
            
            # ⬇️ CONVERTE datetime para string ISO format
            for friend in friends:
                for key, value in friend.items():
                    if hasattr(value, 'isoformat'):  # Verifica se é datetime
                        friend[key] = value.isoformat()
            
            return True, "Amigos recuperados com sucesso", friends
        except mysql.connector.Error as e:
            return False, f"Erro ao buscar amigos: {e}", []
        except Exception as e:
            return False, f"Erro inesperado: {e}", []

    @staticmethod
    def get_pending_requests(user_id):
        """Obtém solicitações de amizade pendentes"""
        try:
            connection = Database.get_connection()
            cursor = connection.cursor(dictionary=True)
            
            cursor.execute(Queries.GET_PENDING_REQUESTS, 
                         (user_id, user_id, user_id, user_id, user_id))
            requests = cursor.fetchall()
            
            # ⬇️ CONVERTE datetime para string ISO format
            for request in requests:
                for key, value in request.items():
                    if hasattr(value, 'isoformat'):  # Verifica se é datetime
                        request[key] = value.isoformat()
            
            return True, "Solicitações recuperadas", requests
        except mysql.connector.Error as e:
            return False, f"Erro ao buscar solicitações: {e}", []
        except Exception as e:
            return False, f"Erro inesperado: {e}", []

    @staticmethod
    def add_friend(user_id, friend_username):
        """Adiciona uma solicitação de amizade e retorna informações do amigo"""
        try:
            connection = Database.get_connection()
            cursor = connection.cursor(dictionary=True)
            
            # Primeiro, busca o ID do amigo pelo username
            cursor.execute("SELECT id, username FROM users WHERE username = %s", (friend_username,))
            friend = cursor.fetchone()
            
            if not friend:
                return False, "Usuário não encontrado", None
            
            friend_id = friend['id']
            friend_username = friend['username']
            
            if user_id == friend_id:
                return False, "Você não pode adicionar a si mesmo", None
            
            # Verifica se já existe uma solicitação (usando sender_id e receiver_id)
            cursor.execute(Queries.CHECK_FRIENDSHIP, 
                        (user_id, friend_id, friend_id, user_id))
            existing = cursor.fetchone()
            
            if existing:
                status = existing['status']
                if status == 'accepted':
                    return False, "Vocês já são amigos", None
                elif status == 'pending':
                    return False, "Solicitação já enviada", None
                elif status == 'rejected':
                    # Permite reenviar solicitação rejeitada
                    pass
            
            # Adiciona solicitação de amizade (usando sender_id e receiver_id)
            cursor.execute(Queries.ADD_FRIEND_REQUEST, (user_id, friend_id))
            connection.commit()
            
            friend_info = {
                'id': friend_id,
                'username': friend_username
            }
            
            return True, "Solicitação de amizade enviada", friend_info
            
        except mysql.connector.Error as e:
            return False, f"Erro ao adicionar amigo: {e}", None
        except Exception as e:
            return False, f"Erro inesperado: {e}", None

    @staticmethod
    def accept_friend_request(user_id, friend_id):
        """Aceita uma solicitação de amizade"""
        try:
            connection = Database.get_connection()
            cursor = connection.cursor()
            
            cursor.execute(Queries.ACCEPT_FRIEND_REQUEST, 
                         (user_id, friend_id, friend_id, user_id))
            connection.commit()
            
            if cursor.rowcount > 0:
                return True, "Solicitação de amizade aceita"
            else:
                return False, "Solicitação não encontrada"
            
        except mysql.connector.Error as e:
            return False, f"Erro ao aceitar solicitação: {e}"
        except Exception as e:
            return False, f"Erro inesperado: {e}"

    @staticmethod
    def reject_friend_request(user_id, friend_id):
        """Rejeita uma solicitação de amizade"""
        try:
            connection = Database.get_connection()
            cursor = connection.cursor()
            
            cursor.execute(Queries.REJECT_FRIEND_REQUEST, 
                         (user_id, friend_id, friend_id, user_id))
            connection.commit()
            
            if cursor.rowcount > 0:
                return True, "Solicitação de amizade rejeitada"
            else:
                return False, "Solicitação não encontrada"
            
        except mysql.connector.Error as e:
            return False, f"Erro ao rejeitar solicitação: {e}"
        except Exception as e:
            return False, f"Erro inesperado: {e}"

    @staticmethod
    def search_users(user_id, query):
        """Busca usuários pelo username"""
        try:
            connection = Database.get_connection()
            cursor = connection.cursor(dictionary=True)
            
            search_query = f"%{query}%"
            cursor.execute(Queries.SEARCH_USERS, (search_query, user_id))
            users = cursor.fetchall()
            
            return True, "Busca realizada", users
        except mysql.connector.Error as e:
            return False, f"Erro na busca: {e}", []
        except Exception as e:
            return False, f"Erro inesperado: {e}", []