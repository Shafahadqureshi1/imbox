import datetime
import re
from typing import Dict

import pytest
from imbox.query import *
from imbox.utils import date_to_date_text


@pytest.fixture
def imap_attribute_lookup() -> Dict[str, str]:
    return {
        "from": "FROM {}",
        "to": "TO {}",
        "sent_since": "SINCE {}",
        "sent_before": "BEFORE {}",
        "subject": "SUBJECT {}",
    }


@pytest.mark.parametrize(
    "kwargs, expected_result",
    [
        ({"from": "email@example.com"}, "FROM email@example.com"),
        ({"to": "email@example.com"}, "TO email@example.com"),
        (
            {"sent_since": datetime.date(2020, 1, 1)},
            f"SINCE {date_to_date_text(datetime.date(2020,1,1))}",
        ),
        (
            {"sent_before": datetime.date(2022, 12, 31)},
            f"BEFORE {date_to_date_text(datetime.date(2022, 12, 31))}",
        ),
        ({"subject": "Hello World"}, "SUBJECT Hello World"),
        ({}, "(ALL)"),
        ({"subject": 'Hello " World'}, "SUBJECT Hello ' World"),
    ],
)
def test_build_search_query(kwargs, expected_result, imap_attribute_lookup):
    assert build_search_query(imap_attribute_lookup, **kwargs) == expected_result


@pytest.mark.parametrize("kwargs", [{"test": "value"}])
def test_build_search_query_invalid_attribute(kwargs, imap_attribute_lookup):
    with pytest.raises(KeyError):
        build_search_query(imap_attribute_lookup, **kwargs)
