import logging


def setup_logger():
    logger = logging.getLogger(__name__)
    formatter = logging.Formatter(
        """
        %(asctime)s - %(levelname)s - %(message)s - %(processName)s
        """
    )
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    return logger


if __name__ == "__main__":
    setup_logger()
