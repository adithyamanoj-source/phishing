import os
import logging
from config import Config

def setup_logging(app=None):
    """Sets up application-wide structured logging to logs/app.log and console."""
    log_dir = os.path.join(Config.BASE_DIR, 'logs')
    os.makedirs(log_dir, exist_ok=True)
    
    log_file = os.path.join(log_dir, 'app.log')
    
    formatter = logging.Formatter(
        '[%(asctime)s] [%(levelname)s] [%(name)s:%(lineno)d] - %(message)s'
    )
    
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(formatter)
    
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)
    
    logger = logging.getLogger('phishguard')
    logger.setLevel(logging.INFO)
    
    if not logger.handlers:
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        
    if app:
        app.logger.addHandler(file_handler)
        app.logger.addHandler(console_handler)
        app.logger.setLevel(logging.INFO)
        
    return logger
