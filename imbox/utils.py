import datetime
import logging
from imaplib import Time2Internaldate
from typing import Optional
logger = logging.getLogger(__name__)


def str_encode(
    value: str, encoding: Optional[str] = None, errors: str = "strict"
) -> bytes:
    """
    Encodes the given string `value` using the specified `encoding` and `errors` parameters.

    Args:
        value: The string value to encode.
        encoding: The encoding to use for encoding the string. If not specified, the default encoding will be used.
        errors: The error handling scheme to use for handling encoding errors. Defaults to 'strict'.

    Returns:
        The encoded string as bytes.

    Raises:
        None

    Examples:
        >>> str_encode('hello', 'utf-8')
        b'hello'
        >>> str_encode('hello', 'ascii', errors='ignore')
        b'hello'
    """
    logger.debug(f"Encode str {value} with encoding {encoding} and errors {errors}")
    return str(value, encoding, errors)


def str_decode(value='', encoding=None, errors='strict'):
    if isinstance(value, str):
        return bytes(value, encoding, errors).decode('utf-8')
    elif isinstance(value, bytes):
        return value.decode(encoding or 'utf-8', errors=errors)
    else:
        raise TypeError("Cannot decode '{}' object".format(value.__class__))


def date_to_date_text(date):
    """Return a date in the RFC 3501 date-text syntax"""
    tzutc = datetime.timezone.utc
    dt = datetime.datetime.combine(date, datetime.time.min, tzutc)
    return Time2Internaldate(dt)[1:12]
