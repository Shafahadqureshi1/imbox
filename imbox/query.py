import datetime

from imbox.utils import date_to_date_text
from typing import Dict, Any


def build_search_query(imap_attribute_lookup: Dict[str, str], **kwargs: Any) -> str:
    """Builds a search query based on the provided IMAP attribute lookup and keyword arguments.

    Args:
        imap_attribute_lookup (dict): A dictionary containing the IMAP attribute lookup.
        **kwargs: Keyword arguments representing the attributes and values to be searched.

    Returns:
        str: The constructed search query.

    Examples:
        >>> imap_attributes = {
        ...     'from': 'FROM "{}"',
        ...     'to': 'TO "{}"',
        ...     'subject': 'SUBJECT "{}"',
        ... }
        >>> query = build_search_query(imap_attributes, from_='example@example.com', subject='Python')
        >>> print(query)
        'FROM "example@example.com" SUBJECT "Python"'
    """
    return (
        " ".join(
            [
                imap_attribute_lookup[name].format(process_value(value))
                for name, value in kwargs.items()
                if value is not None
            ]
        )
        or "(ALL)"
    )


def process_value(value: Any) -> str:
    if isinstance(value, datetime.date):
        value = date_to_date_text(value)
    if isinstance(value, str) and '"' in value:
        value = value.replace('"', "'")
    return value
