class Queries:
    # Users - REGISTRO DE USUÁRIO
    CREATE_USER = """
        INSERT INTO users (username, password) 
        VALUES (%s, %s)
    """
    
    CHECK_USER_EXISTS = """
        SELECT id FROM users WHERE username = %s
    """
    
    GET_USER = """
        SELECT id, username, password, created_at 
        FROM users 
        WHERE username = %s
    """
    
    GET_USER_BY_ID = """
        SELECT id, username, password, created_at 
        FROM users 
        WHERE id = %s
    """
    
    GET_ALL_USERS = """
        SELECT id, username, created_at 
        FROM users 
        ORDER BY username
    """
    
    # User Status - AGORA com user_id
    CREATE_USER_STATUS = """
        INSERT INTO user_status (user_id, is_online, last_seen) 
        VALUES (%s, %s, %s)
    """
    
    UPDATE_USER_STATUS = """
        INSERT INTO user_status (user_id, is_online, last_seen) 
        VALUES (%s, %s, %s) 
        ON DUPLICATE KEY UPDATE 
        is_online = VALUES(is_online), 
        last_seen = VALUES(last_seen)
    """
    
    GET_USER_STATUS = """
        SELECT us.user_id, u.username, us.is_online, us.last_seen 
        FROM user_status us
        JOIN users u ON us.user_id = u.id
        WHERE u.username = %s
    """
    
    GET_USER_STATUS_BY_ID = """
        SELECT us.user_id, u.username, us.is_online, us.last_seen 
        FROM user_status us
        JOIN users u ON us.user_id = u.id
        WHERE us.user_id = %s
    """
    
    GET_ALL_ONLINE_USERS = """
        SELECT u.id, u.username 
        FROM user_status us
        JOIN users u ON us.user_id = u.id
        WHERE us.is_online = TRUE
    """
    
    # Messages (atualizada com user_id)
    SAVE_MESSAGE = """
        INSERT INTO messages (sender_id, receiver_id, content, timestamp) 
        VALUES (%s, %s, %s, %s)
    """
    
    GET_UNDELIVERED_MESSAGES = """
        SELECT m.id, u_sender.username as sender, u_receiver.username as receiver, 
               m.content, m.timestamp 
        FROM messages m
        JOIN users u_sender ON m.sender_id = u_sender.id
        JOIN users u_receiver ON m.receiver_id = u_receiver.id
        WHERE u_receiver.username = %s AND m.delivered = FALSE 
        ORDER BY m.timestamp
    """
    
    MARK_MESSAGES_DELIVERED = """
        UPDATE messages m
        JOIN users u ON m.receiver_id = u.id
        SET m.delivered = TRUE 
        WHERE u.username = %s AND m.delivered = FALSE
    """