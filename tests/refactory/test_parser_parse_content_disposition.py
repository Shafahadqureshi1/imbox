import pytest
from imbox.parser import *


def test_parse_content_disposition_normal():
    content_disposition = 'attachment; filename="test.txt"'
    result = parse_content_disposition(content_disposition)
    assert result == ["attachment", ' filename="test.txt"']


def test_parse_content_disposition_multiple_parameters():
    content_disposition = 'attachment; filename="test.txt"; size="1234"'
    result = parse_content_disposition(content_disposition)
    assert result == ["attachment", ' filename="test.txt"', ' size="1234"']


def test_parse_content_disposition_with_quotes():
    content_disposition = 'attachment; filename="te;st.txt"; size="1234"'
    result = parse_content_disposition(content_disposition)
    assert result == ["attachment", ' filename="te;st.txt"', ' size="1234"']


def test_parse_content_disposition_no_semicolon():
    content_disposition = "attachment"
    result = parse_content_disposition(content_disposition)
    assert result == ["attachment"]


def test_parse_content_disposition_empty():
    content_disposition = "  "
    expected = ["  "]
    result = parse_content_disposition(content_disposition)
    assert result == expected


def test_parse_content_disposition_none():
    content_disposition = None
    result = parse_content_disposition(
        content_disposition if content_disposition else ""
    )
    assert result == []
