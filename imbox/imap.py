from imaplib import IMAP4, IMAP4_SSL

import logging
import ssl as pythonssllib

logger = logging.getLogger(__name__)




class ImapTransport:

    def __init__(
        self,
        hostname: str,
        port: int = None,
        ssl: bool = True,
        ssl_context: pythonssllib.SSLContext = None,
        starttls: bool = False,
    ):
        """
        Initialize an instance of the ImapTransport class.

        This class creates an instance of an IMAP server to interact with,
        it can set up either an IMAP or IMAP over SSL server.
        It uses imaplib's IMAP4 and IMAP4_SSL for the non-SSL and SSL connection respectively.

        Args:
            hostname (str): The host of the email server.
            port (int, optional): The port to connect to the email server on.
                If not provided, it defaults to 993 for ssl=True, or 143 otherwise.
            ssl (bool, optional): If set to True, use a SSL connection. Defaults to True.
            ssl_context (ssl.SSLContext, optional): The SSL context for creating the SSL connection.
                If not provided, a default context is used.
            starttls (bool, optional): If set to True, STARTTLS will be used if available. Defaults to False.
        """
        self.hostname = hostname

        if ssl:
            self.port = port or 993
            if ssl_context is None:
                ssl_context = pythonssllib.create_default_context()
            self.server = IMAP4_SSL(self.hostname, self.port, ssl_context=ssl_context)
        else:
            self.port = port or 143
            self.server = IMAP4(self.hostname, self.port)

        if starttls:
            self.server.starttls()

        logger.debug(
            "Created IMAP4 transport for {host}:{port}".format(
                host=self.hostname, port=self.port
            )
        )

    def list_folders(self):
        logger.debug("List all folders in mailbox")
        return self.server.list()

    def connect(self, username, password):
        self.server.login(username, password)
        self.server.select()
        logger.debug("Logged into server {} and selected mailbox 'INBOX'"
                     .format(self.hostname))
        return self.server
