import datetime

from imbox.utils import date_to_date_text


from typing import Dict

def build_search_query(imap_attribute_lookup: dict, **kwargs: dict) -> str:
    """
    Build a search query string based on the imap_attribute_lookup dictionary
    and input kwargs. If no queries, return "(ALL)". Handles values of type
    datetime.date and strings with quotes correctly.

    Args:
        imap_attribute_lookup(dict): A dictionary containing attributes for
        the IMAP client used to receive emails.
        **kwargs(dict): Variable-length argument list containing attributes
        to be added to the query.

    Returns:
        str: Generated query string for IMAP.

    Example:
        >>> imap_attribute_lookup = {'from': 'FROM "{0}"', 'sent_from':
        'FROM "{0}"'}
        >>> kwargs = {'from': 'example@mail.com', 'sent_from': datetime.date(2022, 1, 1)}
        >>> build_search_query(imap_attribute_lookup, **kwargs)
        'FROM "example@mail.com" FROM "01-Jan-2022"'
    """
    query = []
    for name, value in kwargs.items():
        if value is not None:
            if isinstance(value, datetime.date):
                value = date_to_date_text(value)
            if isinstance(value, str) and '"' in value:
                value = value.replace('"', "'")
            query.append(imap_attribute_lookup[name].format(value))

    if query:
        return " ".join(query)

    return "(ALL)"
