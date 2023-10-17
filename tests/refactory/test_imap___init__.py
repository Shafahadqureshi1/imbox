from imbox.imap import *

import pytest
from unittest.mock import MagicMock, patch
import ssl as pythonssllib


def test_imap_transport_init():
    # Test to check correct initialization of ImapTransport
    imap_transport = ImapTransport("localhost", ssl=True, starttls=True)
    assert imap_transport.hostname == "localhost"
    assert imap_transport.port == 993
    assert imap_transport.server is not None


@patch("imaplib.IMAP4_SSL")
def test_imap_transport_init_ssl(mock_imap4_ssl):
    # Test to check IMAP4_SSL is used when ssl is True
    imap_transport = ImapTransport("localhost", ssl=True, starttls=True)
    mock_imap4_ssl.assert_called_once_with(
        imap_transport.hostname,
        imap_transport.port,
        ssl_context=pythonssllib.create_default_context(),
    )


@patch("imaplib.IMAP4")
def test_imap_transport_init_no_ssl(mock_imap4):
    # Test to check IMAP4 is used when ssl is False
    imap_transport = ImapTransport("localhost", ssl=False)
    mock_imap4.assert_called_once_with(imap_transport.hostname, imap_transport.port)


def test_imap_transport_init_starttls():
    # Test to check starttls is called when starttls is True
    with patch.object(IMAP4, "starttls") as mock_starttls:
        mock_starttls.return_value = True
        imap_transport = ImapTransport("localhost", ssl=True, starttls=True)
        mock_starttls.assert_called_once()


def test_imap_transport_init_starttls_not_called():
    # Test to check starttls is not called when starttls is False
    with patch.object(IMAP4, "starttls") as mock_starttls:
        mock_starttls.return_value = False
        imap_transport = ImapTransport("localhost", ssl=True, starttls=False)
        mock_starttls.assert_not_called()
