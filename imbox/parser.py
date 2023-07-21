import imaplib
import io
import re
import email
import chardet
import base64
import quopri
import time
from datetime import datetime
from email.header import decode_header
from imbox.utils import str_encode, str_decode

import logging
from typing import List, Dict
from imbox.utils import str_decode
from typing import Tuple
from email.message import Message
from typing import Optional, Union, List, Dict
from typing import Optional
from typing import Optional, Dict

logger = logging.getLogger(__name__)


class Struct:
    def __init__(self, **entries):
        self.__dict__.update(entries)

    def keys(self):
        return self.__dict__.keys()

    def __repr__(self):
        return str(self.__dict__)


def decode_mail_header(value: str, default_charset: str = "us-ascii") -> str:
    """
    Decode a header value into a unicode string.

    Args:
        value: The header value to decode.
        default_charset: The default character set for decoding, defaults to 'us-ascii'.

    Returns:
        The decoded unicode string.

    Raises:
        None
    """
    headers = decode_header(value)
    decoded_headers = []
    for text, charset in headers:
        try:
            decoded_text = str_decode(text, charset or default_charset, "replace")
        except LookupError:
            # if the charset is unknown, force default
            decoded_text = str_decode(text, default_charset, "replace")
        decoded_headers.append(decoded_text)
        logger.debug(
            "Mail header: {data} encoding {charset}".format(
                data=decoded_text, charset=charset
            )
        )
    return "".join(decoded_headers)


def fetch_email_by_uid(
    uid: int, connection: imaplib.IMAP4, parser_policy: Optional[Dict] = None
) -> Struct:
    """
    Fetches an email by its UID from the IMAP server.

    Args:
        uid (int): The unique identifier of the email.
        connection (imaplib.IMAP4): The IMAP connection.
        parser_policy (Optional[Dict], optional): The email parser policy. Defaults to None.

    Returns:
        Struct: The parsed email object.
    """
    message, data = connection.uid("fetch", uid, "(BODY.PEEK[] FLAGS)")
    logger.debug("Fetched message for UID {}".format(uid))

    raw_headers = data[0][0] + data[1]
    raw_email = data[0][1]

    email_object = parse_email(raw_email, policy=parser_policy)
    flags = parse_flags(raw_headers.decode())
    email_object.__dict__["flags"] = flags

    return email_object


def decode_content(message: email.message.Message) -> str:
    """
    Decode the content of an email message.

    Args:
        message: The email message to decode.

    Returns:
        The decoded content of the email message as a string.
    """
    content = message.get_payload(decode=True)
    charset = message.get_content_charset("utf-8")

    try:
        return _decode_content_with_charset(content, charset)
    except LookupError:
        encoding = chardet.detect(content).get("encoding")
        if encoding:
            return _decode_content_with_encoding(content, encoding)
        return content
    except AttributeError:
        return content


def _decode_content_with_charset(content: bytes, charset: Optional[str]) -> str:
    if charset is None:
        charset = "utf-8"
    return content.decode(charset, "ignore")


def _decode_content_with_encoding(content: bytes, encoding: str) -> str:
    return content.decode(encoding, "ignore")


def parse_content_disposition(content_disposition: str) -> List[str]:
    """
    Parse the Content-Disposition header and return a list of its parts.

    Args:
        content_disposition: The Content-Disposition header string.

    Returns:
        A list of parts in the Content-Disposition header.

    Example:
        >>> parse_content_disposition('attachment; filename="report.pdf"; size=12345')
        ['attachment', 'filename="report.pdf"', 'size=12345']
    """
    ret = re.split(r';(?=(?:[^"]*"[^"]*")*[^"]*$)', content_disposition)
    return [part.strip() for part in ret]


def parse_attachment(message_part: Union[Message, str]) -> Optional[dict]:
    """
    Parse an attachment from an email message part and return its details.

    Args:
        message_part: The message part containing the attachment.

    Returns:
        A dictionary containing the details of the attachment.

    Raises:
        None.

    Example:
        >>> parse_attachment(message_part)
        {
            'content-type': 'application/pdf',
            'size': 12345,
            'content': <io.BytesIO object at 0x7f86a5c0e580>,
            'content-id': 'attachment1',
            'filename': 'report.pdf',
            'create-date': '2021-01-01'
        }
    """

    def decode_quoted_printable(value: str, encoding: str) -> str:
        # implementation details

        # implementation details

        # implementation details

        return message_part.get_payload(decode=True)

    def get_attachment_content_type(message_part: Message) -> str:
        return message_part.get_content_type()

    def get_attachment_size(file_data: bytes) -> int:
        return len(file_data)

    def get_attachment_content(file_data: bytes) -> io.BytesIO:
        return io.BytesIO(file_data)

    def get_attachment_content_id(message_part: Message) -> Optional[str]:
        return message_part.get("Content-ID", None)

    def get_attachment_create_date(dispositions: List[str]) -> Optional[str]:
        for param in dispositions[1:]:
            if param:
                name, value = decode_param(param)
                if "create-date" in name:
                    return value
        return None

    def decode_param(param: str) -> Tuple[str, str]:
        # implementation details

        # implementation details

        filename_parts = []
        for param in dispositions[1:]:
            if param:
                name, value = decode_param(param)
                if name.rstrip("*") == "filename":
                    if len(name) > 1 and name[1] != "":
                        filename_parts.insert(
                            int(name[1]),
                            value[1:-1] if value.startswith('"') else value,
                        )
                    else:
                        filename_parts.insert(
                            0, value[1:-1] if value.startswith('"') else value
                        )
        return "".join(filename_parts)

    # Check if the message part has a Content-Disposition header
    content_disposition = message_part.get("Content-Disposition", None)
    if content_disposition is not None and not message_part.is_multipart():
        # Split and sanitize the Content-Disposition header
        dispositions = [
            disposition.strip()
            for disposition in parse_content_disposition(content_disposition)
            if disposition.strip()
        ]

        if dispositions[0].lower() in ["attachment", "inline"]:
            file_data = get_attachment_file_data(message_part)
            attachment = {
                "content-type": get_attachment_content_type(message_part),
                "size": get_attachment_size(file_data),
                "content": get_attachment_content(file_data),
                "content-id": get_attachment_content_id(message_part),
            }

            attachment["filename"] = parse_attachment_filename(dispositions)
            attachment["create-date"] = get_attachment_create_date(dispositions)

            return attachment

    return None


def decode_param(param: str) -> Tuple[str, str]:
    """
    Decode a parameter value in an email header.

    Args:
        param: The parameter value to decode.

    Returns:
        A tuple containing the decoded parameter name and value.

    Raises:
        None.

    Examples:
        >>> decode_param('name=?utf-8?B?VGhpcyBpcyBhIHRoaW5nIHZhbHVl?=')
        ('name', 'This is a thing value')

    """

    def decode_quoted_printable(value: str, encoding: str) -> str:
        value = quopri.decodestring(value)
        return str_encode(value, encoding)

    def decode_base64(value: str, encoding: str) -> str:
        value = value.encode()
        missing_padding = len(value) % 4

        if missing_padding:
            value += b"=" * (4 - missing_padding)

        value = base64.b64decode(value)
        return str_encode(value, encoding)

    def decode_value(value: str) -> str:
        match = re.findall(r"=\?((?:\w|-)+)\?([QB])\?(.+?)\?=", value)
        if match:
            for encoding, type_, code in match:
                if type_ == "Q":
                    value = decode_quoted_printable(code, encoding)
                elif type_ == "B":
                    value = decode_base64(code, encoding)
        return value

    name, value = param.split("=", 1)
    values = value.split("\n")
    decoded_values = [decode_value(v) for v in values]
    decoded_value = "".join(decoded_values)

    return name, decoded_value


def get_mail_addresses(
    message: email.message.Message, header_name: str
) -> List[Dict[str, str]]:
    """
    Retrieve all email addresses from a specific message header.

    Args:
        message (email.message.Message): The email message to retrieve the addresses from.
        header_name (str): The name of the header.

    Returns:
        List[Dict[str, str]]: A list of dictionaries, each containing the name and email address.
    """
    headers = [h for h in message.get_all(header_name, [])]
    addresses = email.utils.getaddresses(headers)

    def decode_address(address: Tuple[str, str]):
        address_name, address_email = address
        name = decode_mail_header(address_name)
        logger.debug(
            "{} Mail address in message: <{}> {}".format(
                header_name.upper(), address_name, address_email
            )
        )
        return {"name": name, "email": address_email}

    return [decode_address(address) for address in addresses]


def parse_flags(headers):
    """Copied from https://github.com/girishramnani/gmail/blob/master/gmail/message.py"""
    if len(headers) == 0:
        return []
    headers = bytes(headers, "ascii")
    return list(imaplib.ParseFlags(headers))


def parse_email(raw_email, policy=None):
    if policy is not None:
        email_parse_kwargs = dict(policy=policy)
    else:
        email_parse_kwargs = {}

    # Should first get content charset then str_encode with charset.
    if isinstance(raw_email, bytes):
        email_message = email.message_from_bytes(
            raw_email, **email_parse_kwargs)
        charset = email_message.get_content_charset('utf-8')
        raw_email = str_encode(raw_email, charset, errors='ignore')
    else:
        try:
            email_message = email.message_from_string(
                raw_email, **email_parse_kwargs)
        except UnicodeEncodeError:
            email_message = email.message_from_string(
                raw_email.encode('utf-8'), **email_parse_kwargs)

    maintype = email_message.get_content_maintype()
    parsed_email = {'raw_email': raw_email}

    body = {
        "plain": [],
        "html": []
    }
    attachments = []

    if maintype in ('multipart', 'image'):
        logger.debug("Multipart message. Will process parts.")
        for part in email_message.walk():
            content_type = part.get_content_type()
            part_maintype = part.get_content_maintype()
            content_disposition = part.get('Content-Disposition', None)
            if content_disposition or not part_maintype == "text":
                content = part.get_payload(decode=True)
            else:
                content = decode_content(part)

            is_inline = content_disposition is None \
                or content_disposition.startswith("inline")
            if content_type == "text/plain" and is_inline:
                body['plain'].append(content)
            elif content_type == "text/html" and is_inline:
                body['html'].append(content)
            elif content_disposition:
                attachment = parse_attachment(part)
                if attachment:
                    attachments.append(attachment)

    elif maintype == 'text':
        payload = decode_content(email_message)
        body['plain'].append(payload)

    elif maintype == 'application':
            if email_message.get_content_subtype() == 'pdf':
                attachment = parse_attachment(email_message)
                if attachment:
                    attachments.append(attachment)

    parsed_email['attachments'] = attachments

    parsed_email['body'] = body
    email_dict = dict(email_message.items())

    parsed_email['sent_from'] = get_mail_addresses(email_message, 'from')
    parsed_email['sent_to'] = get_mail_addresses(email_message, 'to')
    parsed_email['cc'] = get_mail_addresses(email_message, 'cc')
    parsed_email['bcc'] = get_mail_addresses(email_message, 'bcc')

    value_headers_keys = ['subject', 'date', 'message-id']
    key_value_header_keys = ['received-spf',
                             'mime-version',
                             'x-spam-status',
                             'x-spam-score',
                             'content-type']

    parsed_email['headers'] = []
    for key, value in email_dict.items():

        if key.lower() in value_headers_keys:
            valid_key_name = key.lower().replace('-', '_')
            parsed_email[valid_key_name] = decode_mail_header(value)

        if key.lower() in key_value_header_keys:
            parsed_email['headers'].append({'Name': key,
                                            'Value': value})

    if parsed_email.get('date'):
        parsed_email['parsed_date'] = email.utils.parsedate_to_datetime(parsed_email['date'])

    logger.info("Downloaded and parsed mail '{}' with {} attachments".format(
        parsed_email.get('subject'), len(parsed_email.get('attachments'))))
    return Struct(**parsed_email)
