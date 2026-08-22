"""Configures and provides logging for js-oracle."""

import logging
from rich.logging import RichHandler


def get_logger(name: str, verbose: bool = False) -> logging.Logger:
    log = logging.getLogger(name)
    level = logging.DEBUG if verbose else logging.INFO

    # Avoid adding duplicate handlers if called multiple times, but still
    # apply the requested level — a later verbose=True call must take effect.
    if log.handlers:
        log.setLevel(level)
        for h in log.handlers:
            h.setLevel(level)
        return log

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
