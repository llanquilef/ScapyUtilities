import logging


class Logger():
    def __init__(self):
        pass

    def get_logger(self):
        return logging.getLogger('scapy')

    def setLevel(self):
        logger = self.get_logger()
        logger.setLevel(logging.WARNING)
        logger.setLevel(logging.INFO)


def main():
    logger = Logger()
    logger.setLevel()


if __name__ == "__main__":
    main()
