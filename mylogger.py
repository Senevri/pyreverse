import logging

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

# Create a file handler and set its logging level
file_handler = logging.FileHandler("logfile.log")
file_handler.setLevel(logging.DEBUG)  # Adjust the logging level as needed

# Create a formatter
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")

# Set the formatter for the file handler
file_handler.setFormatter(formatter)

# Add the file handler to the logger
logger.addHandler(file_handler)
