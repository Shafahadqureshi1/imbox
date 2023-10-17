from imaplib import IMAP4, IMAP4_SSL

import logging
import ssl as pythonssllib

logger = logging.getLogger(__name__)








class ImapTransport:

    def __init__(
        self, server: str, username: str, password: str, use_ssl: bool = False
    ):
        """
        Initialization of ImapTransport class.

        :param server: email server
        :param username: user email
        :param password: user password
        :param use_ssl: bool, default: False
        :return: None
        """
        self.server = server
        self.username = username
        self.password = password
        self.use_ssl = use_ssl

        try:
            self.set_imap_connection()
        except Exception as e:
            raise Exception(f"Failed to initialize ImapTransport: {e}")

        self.set_default_mailbox()

    def list_folders(self):
        logger.debug("List all folders in mailbox")
        return self.server.list()

    def set_imap_connection(self):
        """
        Sets IMAP connection with either IMAP4 or IMAP4_SSL depending on the use_ssl flag.

        :return: None
        """
        cls = IMAP4_SSL if self.use_ssl else IMAP4
        try:
            self.mail_box = cls(self.server)
            logger.info("Mailbox connection established successfully.")
        except pythonssllib.SSLCertVerificationError:
            logger.error(
                "Mailbox connection failed due to SSL certificate verification error."
            )

    def set_default_mailbox(self):
        """
        Sets default mailbox and logs in the user.

        :return: None
        """
        try:
            rv, data = self.mail_box.login(self.username, self.password)
            assert rv == "OK", "Login failed!"
            logger.info("Logged into mailbox successfully.")
        except Exception as e:
            logger.error(f"Failed to login: {e}")
            raise Exception(f"Failed to login: {e}")

    def connect(self, username, password):
        self.server.login(username, password)
        self.server.select()
        logger.debug("Logged into server {} and selected mailbox 'INBOX'"
                     .format(self.hostname))
        return self.server
