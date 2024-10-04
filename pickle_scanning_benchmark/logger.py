import logging
import sys

logging.basicConfig(
    level=logging.INFO,
    format="\n%(asctime)s.%(msecs)03d | %(levelname)s | %(message)s",
    datefmt="%Y/%m/%d %H:%M:%S",
    handlers=[
        # logging.FileHandler(datetime.now().strftime('%Y%m%d_%H%M%S.log')),
        logging.StreamHandler(sys.stdout),
    ]
)

def info(msg):
    logging.info(msg)

def error(msg):
    logging.error(msg)

def warning(msg):
    logging.warning(msg)