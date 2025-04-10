import logging

class Logger:
    def __init__(self, log_file="logs"):
        logging.basicConfig(filename=log_file, level=logging.INFO, format="%(asctime)s - %(message)s")

    def log(self, message):
        print(message)
        logging.info(message)
