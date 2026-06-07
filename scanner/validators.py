from argparse import ArgumentTypeError
from urllib.parse import urlsplit


ALLOWED_SCHEMES: set[str] = {"http", "https"}


def validate_url(value: str) -> str:
    """
    Validate a URL passed through the command line.

    Args:
        value: Raw URL value from argparse.

    Returns:
        Cleaned URL string.

    Raises:
        ArgumentTypeError: If the URL is invalid.
    """
    cleaned_url = value.strip()

    if not cleaned_url:
        raise ArgumentTypeError("Invalid URL: value cannot be empty.")

    if any(character.isspace() for character in cleaned_url):
        raise ArgumentTypeError("Invalid URL: spaces are not allowed.")

    try:
        parsed_url = urlsplit(cleaned_url)
        hostname = parsed_url.hostname
        _ = parsed_url.port
    except ValueError as error:
        raise ArgumentTypeError(f"Invalid URL: {error}") from error

    if parsed_url.scheme.lower() not in ALLOWED_SCHEMES:
        raise ArgumentTypeError(
            "Invalid URL: must start with http:// or https://."
        )

    if hostname is None:
        raise ArgumentTypeError("Invalid URL: hostname is missing.")

    if parsed_url.fragment:
        raise ArgumentTypeError(
            "Invalid URL: fragments like #section are not scan targets."
        )

    return cleaned_url.rstrip("/")