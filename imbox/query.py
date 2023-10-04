import datetime

from imbox.utils import date_to_date_text


from typing import Any

def build_search_query(imap_attribute_lookup: dict, **kwargs: Any) -> str:
    """Build the search query for the IMAP server.

    IMAP server uses this to search for email messages that fit the criteria.

    Args:
        imap_attribute_lookup (dict): The lookup dictionary to map attribute names to values.
        **kwargs (Any): additional attribute-value pairs to be included in the query. If value is a date, it will be converted to text.
                        If value is a string and contains double quotes, they will be replaced with single quotes.

    Returns:
        str: a string representing the final query.
             If no query arguments were provided, returns "(ALL)" to fetch all email messages.
    """

    def prepare_value(value: Any) -> str:
        if isinstance(value, datetime.date):
            return date_to_date_text(value)
        if isinstance(value, str) and '"' in value:
            return value.replace('"', "'")
        return value

    query = [
        f"{imap_attribute_lookup[name].format(prepare_value(value))}"
        for name, value in kwargs.items()
        if value is not None
    ]

    return " ".join(query) if query else "(ALL)"
