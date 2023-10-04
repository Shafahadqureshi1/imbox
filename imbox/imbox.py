import imaplib

from imbox.imap import ImapTransport
from imbox.messages import Messages

import logging

from imbox.vendors import GmailMessages, hostname_vendorname_dict, name_authentication_string_dict
from imbox.vendors import hostname_vendorname_dict, name_authentication_string_dict

logger = logging.getLogger(__name__)








class Imbox:

    def __init__(
        self,
        hostname,
        username=None,
        password=None,
        ssl=True,
        ssl_context=None,
        starttls=False,
        port=None,
        vendor_name=None,
    ):
        if vendor_name and vendor_name in name_authentication_string_dict:
            (
                self.username,
                self.password,
                self.ssl_context,
            ) = name_authentication_string_dict[vendor_name]
        self.set_authentication_string(username, password)
        self.set_vendor_string(hostname, vendor_name)
        self.transport = ImapTransport(
            hostname, ssl=ssl, ssl_context=ssl_context, starttls=starttls, port=port
        )

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.logout()

    def logout(self):
        self.connection.close()
        self.connection.logout()
        logger.info("Disconnected from IMAP Server {username}@{hostname}".format(
            hostname=self.hostname, username=self.username))

    def mark_seen(self, uid):
        logger.info("Mark UID {} with \\Seen FLAG".format(int(uid)))
        self.connection.uid('STORE', uid, '+FLAGS', '(\\Seen)')

    def mark_flag(self, uid):
        logger.info("Mark UID {} with \\Flagged FLAG".format(int(uid)))
        self.connection.uid('STORE', uid, '+FLAGS', '(\\Flagged)')

    def delete(self, uid):
        logger.info(
            "Mark UID {} with \\Deleted FLAG and expunge.".format(int(uid)))
        self.connection.uid('STORE', uid, '+FLAGS', '(\\Deleted)')
        self.connection.expunge()

    def copy(self, uid, destination_folder):
        logger.info("Copy UID {} to {} folder".format(
            int(uid), str(destination_folder)))
        return self.connection.uid('COPY', uid, destination_folder)

    def move(self, uid, destination_folder):
        logger.info("Move UID {} to {} folder".format(
            int(uid), str(destination_folder)))
        if self.copy(uid, destination_folder):
            self.delete(uid)

    def messages(self, **kwargs):
        folder = kwargs.get('folder', False)

        messages_class = Messages

        if self.vendor == 'gmail':
            messages_class = GmailMessages

        if folder:
            self.connection.select(
                messages_class.FOLDER_LOOKUP.get((folder.lower())) or folder)
            msg = " from folder '{}'".format(folder)
            del kwargs['folder']
        else:
            msg = " from inbox"

        logger.info("Fetch list of messages{}".format(msg))

        return messages_class(connection=self.connection,
                              parser_policy=self.parser_policy,
                              **kwargs)

    def folders(self):
        return self.connection.list()
