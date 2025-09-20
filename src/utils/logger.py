import logging

def setup_logger():
    logger = logging.getLogger('chat_server')
    logger.setLevel(logging.DEBUG)
    
    # Create handlers
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG)
    
    # Create formatters
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    console_handler.setFormatter(formatter)
    
    # Add handlers to logger
    logger.addHandler(console_handler)
    
    return logger