"""Shared URL validation, normalization, and construction utilities."""

from urllib.parse import urljoin, urlparse, urlunparse

from security_scanner.core import InvalidURLError

ALLOWED_SCHEMES: set[str] = {"http", "https"}


def normalize_url(raw_url: str) -> str:
    """Validate and normalize a URL before scanning.

    If the user provides a hostname without a scheme, HTTPS is assumed.

    Args:
        raw_url: URL or hostname provided by the user.

    Returns:
        A normalized URL string.

    Raises:
        InvalidURLError: If the URL is empty, malformed, or uses an unsupported
            scheme.
    """
    cleaned_url = raw_url.strip()

    # Empty or whitespace-only input cannot be safely normalized.
    if not cleaned_url:
        raise InvalidURLError("URL cannot be empty.")

    if any(character.isspace() for character in cleaned_url):
        raise InvalidURLError("URL cannot contain spaces.")

    if "://" not in cleaned_url:
        # Internal fetchers may receive a bare hostname; HTTPS is the safer
        # default because it tests the encrypted version first.
        cleaned_url = f"https://{cleaned_url}"

    try:
        parsed_url = urlparse(cleaned_url)
        hostname = parsed_url.hostname
        # Accessing parsed_url.port forces urllib to validate malformed ports.
        _ = parsed_url.port
    except ValueError as error:
        raise InvalidURLError(f"Malformed URL: {error}") from error

    if parsed_url.scheme.lower() not in ALLOWED_SCHEMES:
        raise InvalidURLError(
            f"Unsupported URL scheme '{parsed_url.scheme}'. "
            "Only http and https are supported."
        )

    if hostname is None:
        raise InvalidURLError("URL hostname is missing.")

    normalized_url = urlunparse(
        parsed_url._replace(scheme=parsed_url.scheme.lower())
    )

    # Removing one trailing slash keeps equivalent roots consistent in reports.
    return normalized_url.rstrip("/")


def build_root_path_url(base_url: str, path: str) -> str:
    """Build a root-relative URL such as https://site.com/.env."""
    return urljoin(base_url, path)
