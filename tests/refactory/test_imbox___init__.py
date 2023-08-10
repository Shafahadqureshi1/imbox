import logging
from imaplib import IMAP4
from unittest.mock import Mock, patch

import pytest
from imbox.imbox import *
from imbox.vendors import hostname_vendorname_dict


import logging
from imaplib import IMAP4
from unittest.mock import Mock, patch

import pytest
from imbox.imbox import Imbox
from imbox.vendors import hostname_vendorname_dict


@pytest.fixture
def mocked_imap_transport():
    with patch("imbox.imbox.ImapTransport") as mock_transport:
        connection = Mock(spec=IMAP4)
        mock_transport.return_value.connect.return_value = connection
        yield mock_transport


@pytest.fixture
def test_logger():
    return [
        log
        for log in logging.getLogger().handlers
        if isinstance(log, logging.NullHandler)
    ]


def test_initialization_valid_parameters(mocked_imap_transport, test_logger):
    username = "username"
    hostname = "hostname"
    password = "password"
    mock_transport = mocked_imap_transport.return_value
    mock_transport.connect.return_value = None
    imbox = Imbox(hostname, username=username, password=password)
    assert imbox.server is mock_transport
    assert imbox.hostname == hostname
    assert imbox.username == username
    assert imbox.password == password
    assert imbox.vendor == hostname_vendorname_dict.get(hostname)
    assert imbox.connection is None
    assert test_logger


def test_initialization_invalid_parameters(mocked_imap_transport):
    mock_transport = mocked_imap_transport.return_value
    mock_transport.connect.side_effect = IMAP4.error
    with pytest.raises(IMAP4.error):
        Imbox("hostname", username="username", password="wrong_password")
