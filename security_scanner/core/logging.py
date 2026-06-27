"""Logging setup for the security scanner."""

import logging

LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"


def configure_logging(verbose: bool = False) -> None:
    """
    Configure consistent logging for the scanner.

    Args:
        verbose: If True, enable debug logging. Otherwise show warnings and
            errors only.
    """
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.WARNING,
        format=LOG_FORMAT,
        force=True,
    )
