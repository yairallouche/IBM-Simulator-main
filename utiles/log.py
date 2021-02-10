# IBM Confidential - OCO Source Materials
# (C) Copyright IBM Corp. 2020
# The source code for this program is not published or otherwise divested of its trade secrets,
# irrespective of what has been deposited with the U.S. Copyright Office.

__author__ = "IBM"

import logging
import os
import sys

_logger = None
_log_file_path = None


def init(level, path):
    """Create a logger.
    :param level: Log level to record.
    :param path: A file path to save logs.
    :return: Logger instance.
    """
    global _logger
    global _log_file_path
    if not os.path.exists(path):
        os.makedirs(path)


    fmt = logging.Formatter("%(asctime)s [%(module)s.%(funcName)s] [%(threadName)s] [%(levelname)s] - %(message)s")
    _log_file_path = os.path.join(path, f"algo.log")
    h1 = logging.FileHandler(filename=_log_file_path)
    h1.setLevel(level)
    h1.setFormatter(fmt)

    h2 = logging.StreamHandler(sys.stdout)
    h2.setLevel(logging.INFO)
    h2.setFormatter(fmt)

    if _logger:
        for handler in _logger.handlers[:]:
            _logger.removeHandler(handler)

    _logger = logging.getLogger(__name__)
    _logger.addHandler(h1)
    _logger.addHandler(h2)
    _logger.setLevel(level)

def get_log_file_path():
    global _log_file_path
    return _log_file_path

def debug(msg):
    global _logger
    if _logger:
        _logger.debug(msg)


def info(msg):
    global _logger
    if _logger:
        _logger.info(msg)


def warning(msg):
    global _logger
    if _logger:
        _logger.warning(msg)


def error(msg):
    global _logger
    if _logger:
        _logger.error(msg)
