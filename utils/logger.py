"""Configures and provides logging for js-oracle."""

import logging
from rich.logging import RichHandler


def get_logger(name: str, verbose: bool = False) -> logging.Logger:
    log = logging.getLogger(name)

    # Avoid adding duplicate handlers if called multiple times
    if log.handlers:
        return log

    level = logging.DEBUG if verbose else logging.INFO
    log.setLevel(level)

    handler = RichHandler(
        level=level,
        show_time=True,
        show_level=True,
        show_path=False,
        log_time_format="[%H:%M:%S]",
    )
    handler.setFormatter(logging.Formatter("%(message)s"))
    log.addHandler(handler)

    # Prevent messages from bubbling to the root logger
    log.propagate = False

    return log


logger = get_logger("js-oracle")
