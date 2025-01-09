import logging

# Configure the logging system
LOG_FILE_PATH = '/var/log/certificate-controller.log'

logging.basicConfig(
    filename=LOG_FILE_PATH,  # Shared log file path
    level=logging.INFO,      # Adjust the log level as needed
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger.info('Certificate controller service started.')


# Create a logger for other modules
def get_logger(name):
    return logging.getLogger(name)

