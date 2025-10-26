import threading
import signal
import sys
import time
import logging
import asyncio
from src.protocols.tcp_server import TCPServer
from src.protocols.websocket_server import WebSocketServer
from src.config.config import Config

# Configuração de logging
logging.basicConfig(
    level=getattr(logging, Config.LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class ChatServer:
    def __init__(self):
        self.tcp_server = None
        self.websocket_server = None
        self.running = False
        
    def start_servers(self):
        """Inicia ambos os servidores (TCP e WebSocket)"""
        try:
            logger.info("🚀 Iniciando servidor de chat...")
            
            # Testar conexão com o banco de dados primeiro
            logger.info("🔍 Testando conexão com o banco de dados...")
            
            try:
                import mysql.connector
                connection = mysql.connector.connect(
                    host=Config.DB_HOST,
                    port=Config.DB_PORT,
                    database=Config.DB_NAME,
                    user=Config.DB_USER,
                    password=Config.DB_PASSWORD
                )
                
                if connection.is_connected():
                    logger.info("✅ Conexão com banco de dados estabelecida!")
                    
                    # Verificar tabelas
                    cursor = connection.cursor()
                    cursor.execute("SHOW TABLES")
                    tables = [table[0] for table in cursor.fetchall()]
                    logger.info(f"📊 Tabelas encontradas: {tables}")
                    
                    cursor.close()
                    connection.close()
                else:
                    logger.error("❌ Falha na conexão com o banco de dados")
                    return False
                    
            except Exception as e:
                logger.error(f"❌ Erro na conexão com o banco: {e}")
                return False
            
            logger.info("📡 Iniciando servidores TCP e WebSocket...")
            
            self.tcp_server = TCPServer()
            tcp_thread = threading.Thread(target=self.tcp_server.start, daemon=True)
            tcp_thread.start()
            
            self.websocket_server = WebSocketServer()
            
            def start_ws():
                asyncio.set_event_loop(asyncio.new_event_loop())
                self.websocket_server.start()

            ws_thread = threading.Thread(target=start_ws, daemon=True)
            ws_thread.start()
            
            self.running = True
            logger.info(f"✅ Servidor TCP rodando em {Config.TCP_HOST}:{Config.TCP_PORT}")
            logger.info(f"✅ Servidor WebSocket rodando em {Config.WS_HOST}:{Config.WS_PORT}")
            logger.info("🎉 Servidor pronto para conexões!")
            
            return True
            
        except Exception as e:
            logger.error(f"💥 Erro ao iniciar servidores: {e}")
            return False
    
    def stop_servers(self):
        """Para ambos os servidores"""
        logger.info("🛑 Parando servidores...")
        self.running = False
        
        if self.tcp_server:
            self.tcp_server.stop()
        
        if self.websocket_server:
            self.websocket_server.stop()
        
        logger.info("👋 Servidores parados com sucesso")

def signal_handler(sig, frame):
    """Handler para Ctrl+C"""
    print("\n🛑 Recebido sinal de interrupção (Ctrl+C)")
    server.stop_servers()
    sys.exit(0)

if __name__ == "__main__":
    server = ChatServer()
    
    # Configura handler para Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)
    
    print("=" * 50)
    print("🚀 Chat Server - Segurança da Informação")
    print("=" * 50)
    
    if server.start_servers():
        try:
            print("✅ Servidor iniciado com sucesso!")
            print("📱 Aguardando conexões...")
            print("💡 Pressione Ctrl+C para parar o servidor")
            
            # Mantém o programa rodando
            while server.running:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n🛑 Parando servidor...")
            server.stop_servers()
    else:
        logger.error("❌ Falha ao iniciar servidores")
        sys.exit(1)