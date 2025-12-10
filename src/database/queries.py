class Queries:
    # Queries de Usuário
    CHECK_USER_EXISTS = "SELECT id FROM users WHERE username = %s"
    CREATE_USER = "INSERT INTO users (username, password, public_key, salt) VALUES (%s, %s, %s, %s)"    
    GET_USER_BY_USERNAME = "SELECT id, username, password, public_key, salt, created_at FROM users WHERE username = %s"
    GET_USER_BY_ID = "SELECT id, username, password, public_key, salt, created_at FROM users WHERE id = %s"
    GET_USER_ID = "SELECT id FROM users WHERE username = %s"
    GET_ALL_USERS = "SELECT id, username, public_key, created_at, updated_at FROM users WHERE id != %s"
    
    # Queries de Status do Usuário
    CREATE_USER_STATUS = "INSERT INTO user_status (user_id, is_online) VALUES (%s, %s)"
    UPDATE_USER_STATUS = "UPDATE user_status SET is_online=%s, last_seen=%s WHERE user_id=%s"

    CHECK_USER_ONLINE = "SELECT is_online FROM user_status WHERE user_id = %s"
    GET_ONLINE_USERS = """
        SELECT u.id, u.username, u.public_key
        FROM users u 
        JOIN user_status us ON u.id = us.user_id 
        WHERE us.is_online = TRUE AND u.id != %s
    """
    
    # Queries de Mensagens
    INSERT_MESSAGE = """
        INSERT INTO messages (sender_id, receiver_id, content) 
        VALUES (%s, %s, %s)
    """
    
    GET_CONVERSATION_HISTORY = """
        SELECT m.id, m.sender_id, m.receiver_id, m.content, m.timestamp, m.delivered,
               u1.username as sender_username, u2.username as receiver_username
        FROM messages m
        JOIN users u1 ON m.sender_id = u1.id
        JOIN users u2 ON m.receiver_id = u2.id
        WHERE (m.sender_id = %s AND m.receiver_id = %s) 
           OR (m.sender_id = %s AND m.receiver_id = %s)
        ORDER BY m.timestamp DESC
        LIMIT %s
    """
    
    # Queries para mensagens pendentes (usando a coluna 'delivered')
    GET_UNDELIVERED_MESSAGES = """
        SELECT m.id, m.sender_id, m.receiver_id, m.content, m.timestamp,
               u.username as sender_username
        FROM messages m
        JOIN users u ON m.sender_id = u.id
        WHERE m.receiver_id = %s AND m.delivered = FALSE
        ORDER BY m.timestamp ASC
    """
    
    MARK_MESSAGES_DELIVERED = "UPDATE messages SET delivered = TRUE WHERE receiver_id = %s AND delivered = FALSE"
    
    GET_LAST_MESSAGE_ID = """
        SELECT id FROM messages 
        WHERE sender_id = %s AND receiver_id = %s AND content = %s 
        ORDER BY timestamp DESC LIMIT 1
    """

    GET_ALL_CONTACTS = """
        SELECT u.id, u.username, us.is_online, us.last_seen
        FROM users u
        LEFT JOIN user_status us ON u.id = us.user_id
        WHERE u.id != %s
        ORDER BY us.is_online DESC, u.username ASC
    """
    
    #! Queries de Amizades
    CREATE_FRIEND_REQUEST = """
        INSERT INTO friend_requests (sender_id, receiver_id, status, sender_public_key) 
        VALUES (%s, %s, 'pending', %s)
    """

    GET_FRIEND_REQUESTS = """
        SELECT 
            fr.id,
            fr.sender_id,
            u.username as sender_username,
            fr.status,
            fr.created_at,
            fr.sender_public_key
        FROM friend_requests fr
        JOIN users u ON fr.sender_id = u.id
        WHERE fr.receiver_id = %s AND fr.status = 'pending'
    """

    UPDATE_FRIEND_STATUS = """
        UPDATE friend_requests 
        SET status = %s, receiver_public_key = %s
        WHERE id = %s
    """

    GET_FRIENDS_LIST = """
        SELECT 
            u.id,
            u.username,
            fr.created_at,
            us.is_online,
            us.last_seen
        FROM friend_requests fr
        JOIN users u ON (
            (fr.sender_id = %s AND fr.receiver_id = u.id) OR 
            (fr.sender_id = u.id AND fr.receiver_id = %s)
        )
        JOIN user_status us ON u.id = us.user_id
        WHERE fr.status = 'accepted'
        ORDER BY u.username
    """
    CHECK_EXISTING_FRIENDSHIP = """
        SELECT id, status 
        FROM friend_requests 
        WHERE (sender_id = %s AND receiver_id = %s) OR (sender_id = %s AND receiver_id = %s)
    """