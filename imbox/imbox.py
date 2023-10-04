import imaplib

from imbox.imap import ImapTransport
from imbox.messages import Messages

import logging

from imbox.vendors import GmailMessages, hostname_vendorname_dict, name_authentication_string_dict
from imbox.vendors import hostname_vendorname_dict, name_authentication_string_dict
from typing import List, Dict, Union, Optional
from imaplib import IMAP4
from typing import Any

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


    def messages(self, unread=None, starred=None, folder=None, uid=None):
        if folder:
            self.mailbox.select_folder(folder)

        search_criteria = self._build_search_criteria(unread, starred, uid)
        response, message_id_numbers = self.mailbox.uid("search", None, search_criteria)

        if response == "OK":
            for message_id_number in message_id_numbers[0].split():
                yield self._fetch_email_by(message_id_number)

    def folders(self):
        return self.connection.list()

    def _build_search_criteria(self, unread, starred, uid):
        email_filters = self._set_email_filters(unread, starred, uid)
        return "({})".format(" ".join(email_filters))

    def _set_email_filters(self, unread, starred, uid):
        email_filters = ["ALL"]

        if unread:
            email_filters.append("UNSEEN")
        if starred:
            email_filters.append("FLAGGED")
        if uid:
            email_filters.append("UID {}".format(uid))

        return email_filters

    def _fetch_email_by(self, message_id_number):
        response, email_data = self.mailbox.uid("fetch", message_id_number, "(BODY[])")
        raw_email = email_data[0][1]
        return self._parse_email_from(raw_email)
