-- Criar database (se não existir)
CREATE DATABASE IF NOT EXISTS chat_db 
CHARACTER SET utf8mb4 
COLLATE utf8mb4_unicode_ci;

-- Usar o database
USE chat_db;

-- Tabela de usuários (PRIMEIRO criar users)
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- Tabela para status dos usuários (AGORA com user_id)
CREATE TABLE IF NOT EXISTS user_status (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    is_online BOOLEAN DEFAULT FALSE,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE KEY unique_user_status (user_id)
) ENGINE=InnoDB;

-- Tabela de mensagens (atualizada com user_id)
CREATE TABLE IF NOT EXISTS messages (
    id INT AUTO_INCREMENT PRIMARY KEY,
    sender_id INT NOT NULL,
    receiver_id INT NOT NULL,
    content TEXT NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    delivered BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (receiver_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- Criar índices para melhor performance
CREATE INDEX idx_user_status_user_id ON user_status(user_id);
CREATE INDEX idx_messages_sender_id ON messages(sender_id);
CREATE INDEX idx_messages_receiver_id ON messages(receiver_id);
CREATE INDEX idx_messages_timestamp ON messages(timestamp);

-- Criar usuário para o aplicativo (se não existir)
CREATE USER IF NOT EXISTS 'chat_user'@'localhost' IDENTIFIED BY 'chat_password';
GRANT ALL PRIVILEGES ON chat_db.* TO 'chat_user'@'localhost';
FLUSH PRIVILEGES;

-- Verificar tabelas criadas
SHOW TABLES;

-- Mostrar estrutura das tabelas
DESCRIBE users;
DESCRIBE user_status;
DESCRIBE messages;