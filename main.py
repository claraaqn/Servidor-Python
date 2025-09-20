import argparse
import sys
import signal
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

try:
    from src.server import ChatServer
    from src.utils.logger import setup_logger
    print("Importações bem-sucedidas!")
except ImportError as e:
    print(f"Erro de importação: {e}")
    print("Verifique a estrutura de pastas e arquivos __init__.py")
    sys.exit(1)

logger = setup_logger()

def parse_arguments():
    parser = argparse.ArgumentParser(description='Servidor de Chat TCP/IP')
    
    parser.add_argument('--host', default='localhost', help='Endereço do host')
    parser.add_argument('--port', type=int, default=8080, help='Porta do servidor')  # ⬅️ FORÇA 8080 AQUI
    parser.add_argument('--debug', action='store_true', help='Modo debug')
    parser.add_argument('--version', action='version', version='Servidor de Chat v1.0.0')
    
    return parser.parse_args()

def signal_handler(sig, frame):
    """Handler para signals de interrupção"""
    logger.info("\nRecebido sinal de interrupção. Encerrando servidor...")
    sys.exit(0)

def main():
    """Função principal do servidor"""
    try:
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        args = parse_arguments()
        
        print("=" * 50)
        print("SERVIDOR DE CHAT - INICIANDO")
        print("=" * 50)
        
        logger.info(f"Host: {args.host}")
        logger.info(f"Porta: {args.port}")
        logger.info("Aguardando conexões...")
        
        server = ChatServer()
        server.host = args.host
        server.port = args.port  # ⬅️ USA A PORTA DOS ARGUMENTOS
        
        server.start_server()
        
    except KeyboardInterrupt:
        logger.info("\nServidor interrompido pelo usuário")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Erro fatal: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()