import logging, os

# Configure the logging system
LOG_FILE_PATH = '/var/log/certificate_controller/certificate_controller.log'

log_dir = os.path.dirname(LOG_FILE_PATH)

if not os.path.exists(log_dir):
    os.makedirs(log_dir)

logging.basicConfig(
    filename=LOG_FILE_PATH,  # Shared log file path
    level=logging.INFO,      # Adjust the log level as needed
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

logger.info('Certificate controller service started.')


# Create a logger for other modules
def get_logger(name):
    return logging.getLogger(name)

