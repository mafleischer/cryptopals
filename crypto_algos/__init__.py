import logging
from logging.handlers import RotatingFileHandler

log_formatter = logging.Formatter(
    '%(asctime)s %(levelname)s %(module)s %(funcName)s(%(lineno)d):\n %(message)s')

handler = RotatingFileHandler(
    'debug.log', mode='a', maxBytes=12000000, backupCount=0, encoding=None, delay=0)

handler.setFormatter(log_formatter)
handler.setLevel(logging.DEBUG)

logger = logging.getLogger('root')
logger.setLevel(logging.DEBUG)

logger.addHandler(handler)