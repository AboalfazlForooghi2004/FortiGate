# logging_config.py
"""
Logging configuration for FortiGate automation scripts.

- Sets up a logger that writes to:
    1. Syslog (INFO+)
    2. Console (WARNING+)
- Prevents duplicate handlers when imported multiple times.
"""

import logging
import logging.handlers
import os

# ----------------------- Configuration -----------------------
# Default to localhost if not provided in environment
SYSLOG_SERVER = os.getenv("SYSLOG_SERVER", "localhost")
SYSLOG_PORT = int(os.getenv("SYSLOG_PORT", "514"))


def setup_syslog_logger(name: str = "phase3") -> logging.Logger:
    """
    Set up a logger with both syslog and console handlers.

    Args:
        name (str): Logger name, typically the phase or module name.

    Returns:
        logging.Logger: Configured logger instance.
    """
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)  # Capture all levels internally

    # Prevent adding multiple handlers if logger already configured
    if logger.handlers:
        return logger

    # ----------------- Syslog Handler -----------------
    try:
        syslog_handler = logging.handlers.SysLogHandler(address=(SYSLOG_SERVER, SYSLOG_PORT))
        syslog_handler.setLevel(logging.INFO)  # Info+ goes to syslog
        syslog_formatter = logging.Formatter('%(name)s %(levelname)s: %(message)s')
        syslog_handler.setFormatter(syslog_formatter)
        logger.addHandler(syslog_handler)
    except Exception as e:
        print(f" Failed to set up Syslog handler: {e}")

    # ----------------- Console Handler -----------------
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.WARNING)  # Warnings+ to console
    console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    # Prevent log messages from propagating to the root logger
    logger.propagate = False

    return logger


# ----------------------- Example Usage -----------------------
if __name__ == "__main__":
    log = setup_syslog_logger("test_logger")
    log.debug("This is a debug message (won't show on console)")
    log.info("This is an info message (goes to syslog)")
    log.warning("This is a warning message (console + syslog)")
    log.error("This is an error message (console + syslog)")
