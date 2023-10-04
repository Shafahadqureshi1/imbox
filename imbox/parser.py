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
from email.message import Message
import email.errors


from typing import Tuple
from typing import Tuple, List
from imbox.utils import str_encode


from typing import List, Tuple
from email.policy import Policy


from typing import Struct

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
        value (str): The header value to be decoded.
        default_charset (str, optional): The default encoding to be used if it can't
        be determined from the header value. Defaults to 'us-ascii'.

    Returns:
        str: The decoded header value as a unicode string.
    """
    try:
        headers = decode_header(value)
    except email.errors.HeaderParseError:
        return str_decode_with_replacement(value, default_charset)

    return process_and_join_headers(headers, default_charset)

def parse_content_disposition(content_disposition: str) -> List[str]:
    """
    Parses a string representing a Content-Disposition header value.
    It splits the string on semicolons to separate the different parts of the header, ignoring semicolons that are inside quotations.
    The parts of the header are returned as a list of strings.
    If the input is an empty string, an empty list is returned.

    Parameters
    ----------
    content_disposition : str
        The string representing the Content-Disposition header value.

    Returns
    -------
    list
        The parts of the header as a list of strings.
    """

    def append_to_result(
        ret: List[str], idx: str, content: str, in_quote: bool
    ) -> Tuple[List[str], bool]:
        if content[idx] == ";":
            # Check if not in quote
            if not in_quote:
                ret.append(content[:idx])
                return content[idx + 1 :], False
        elif content[idx] in {'"', "'"}:
            in_quote = not in_quote
        return content, in_quote

    def split_content_disposition(input_str: str):
        in_quote = False
        ret = []

        while input_str:
            input_str, in_quote = append_to_result(ret, 0, input_str, in_quote)

        return ret

    return split_content_disposition(content_disposition)

def parse_attachment(message_part: Message) -> dict:
    """
    Given function decodes the attachment in email.
    """
    content_disposition = message_part.get("Content-Disposition", None)

    # Returns None if no attachment
    if not (is_valid_attachment(content_disposition, message_part)):
        return None

    return create_attachment_data(dispositions, message_part)


def get_mail_addresses(message, header_name):
    """
    Retrieve all email addresses from one message header.
    """
    headers = [h for h in message.get_all(header_name, [])]
    addresses = email.utils.getaddresses(headers)

    for index, (address_name, address_email) in enumerate(addresses):
        addresses[index] = {'name': decode_mail_header(address_name),
                            'email': address_email}
        logger.debug("{} Mail address in message: <{}> {}".format(
            header_name.upper(), address_name, address_email))
    return addresses


def is_valid_attachment(content_disposition: str, message_part: Message) -> bool:
    """
    This function verifies if the part of the message is a valid attachment
    """
    if content_disposition is None or message_part.is_multipart():
        return False
    dispositions = parse_dispositions(content_disposition)
    return dispositions[0].lower() in ["attachment", "inline"]


def parse_email(raw_email: str, policy=None) -> Struct:
    if policy is not None:
        email_parse_kwargs = dict(policy=policy)
    else:
        email_parse_kwargs = {}

    # Get content charset then str_encode with charset.
    if isinstance(raw_email, bytes):
        email_message = email.message_from_bytes(raw_email, **email_parse_kwargs)
        charset = email_message.get_content_charset("utf-8")
        raw_email = str_encode(raw_email, charset, errors="ignore")
    else:
        try:
            email_message = email.message_from_string(raw_email, **email_parse_kwargs)
        except UnicodeEncodeError:
            email_message = email.message_from_string(
                raw_email.encode("utf-8"), **email_parse_kwargs
            )

    parsed_email = {"raw_email": raw_email}
    maintype = email_message.get_content_maintype()

    # Process based on content type
    if maintype in ("multipart", "image"):
        body, attachments = process_multipart_message(email_message)
    elif maintype == "text":
        body = process_text_message(email_message)
        attachments = []
    elif maintype == "application":
        attachments = process_application_message(email_message)
        body = {"plain": [], "html": []}

    parsed_email["body"] = body
    parsed_email["attachments"] = attachments

    email_dict = dict(email_message.items())
    header_dict = process_headers(email_dict)
    parsed_email = {**parsed_email, **header_dict}

    parsed_email["sent_from"] = get_mail_addresses(email_message, "from")
    parsed_email["sent_to"] = get_mail_addresses(email_message, "to")
    parsed_email["cc"] = get_mail_addresses(email_message, "cc")
    parsed_email["bcc"] = get_mail_addresses(email_message, "bcc")

    if parsed_email.get("date"):
        parsed_email["parsed_date"] = email.utils.parsedate_to_datetime(
            parsed_email["date"]
        )

    logger.info(
        "Parsed mail '{}' with {} attachments".format(
            parsed_email.get("subject"), len(parsed_email.get("attachments"))
        )
    )
    return Struct(**parsed_email)


def parse_dispositions(content_disposition: str) -> List[str]:
    """
    Parses the content disposition to ignore any empty strings and strips each disposition
    """
    return [
        disposition.strip()
        for disposition in parse_content_disposition(content_disposition)
        if disposition.strip()
    ]

def process_multipart_message(email_message: Message):
    """Process multipart email message."""
    body = {"plain": [], "html": []}
    attachments = []

    logger.debug("Multipart message. Will process parts.")
    for part in email_message.walk():
        content_type = part.get_content_type()
        part_maintype = part.get_content_maintype()
        content_disposition = part.get("Content-Disposition", None)
        if content_disposition or not part_maintype == "text":
            content = part.get_payload(decode=True)
        else:
            content = decode_content(part)

        is_inline = content_disposition is None or content_disposition.startswith(
            "inline"
        )
        if content_type == "text/plain" and is_inline:
            body["plain"].append(content)
        elif content_type == "text/html" and is_inline:
            body["html"].append(content)
        elif content_disposition:
            attachment = parse_attachment(part)
            if attachment:
                attachments.append(attachment)
    return body, attachments


def process_text_message(email_message: Message):
    """Process text email message."""
    body = {"plain": [], "html": []}
    payload = decode_content(email_message)
    body["plain"].append(payload)
    return body


def process_application_message(email_message: Message):
    """Process application email message."""
    attachments = []
    if email_message.get_content_subtype() == "pdf":
        attachment = parse_attachment(email_message)
        if attachment:
            attachments.append(attachment)
    return attachments


def process_headers(email_dict: dict):
    """Process various headers."""
    parsed_email = {}
    value_headers_keys = ["subject", "date", "message-id"]
    key_value_header_keys = [
        "received-spf",
        "mime-version",
        "x-spam-status",
        "x-spam-score",
        "content-type",
    ]

    parsed_email["headers"] = []
    for key, value in email_dict.items():
        if key.lower() in value_headers_keys:
            valid_key_name = key.lower().replace("-", "_")
            parsed_email[valid_key_name] = decode_mail_header(value)

        if key.lower() in key_value_header_keys:
            parsed_email["headers"].append({"Name": key, "Value": value})
    return parsed_email


def create_attachment_data(dispositions: List[str], message_part: Message) -> dict:
    """
    This function creates the data for the valid attachment which includes,
    file's content-type, size, content and its id.
    """
    file_data = message_part.get_payload(decode=True)
    attachment = create_basic_attachment_data(file_data, message_part)
    filename_parts = create_filename_parts(dispositions)
    attachment["filename"] = "".join(filename_parts)
    return attachment


def create_basic_attachment_data(file_data: str, message_part: Message) -> dict:
    """
    This function creates the basic info of the attachment.
    """
    return {
        "content-type": message_part.get_content_type(),
        "size": len(file_data),
        "content": io.BytesIO(file_data),
        "content-id": message_part.get("Content-ID", None),
    }


def create_filename_parts(dispositions: List[str]) -> List[str]:
    """
    This function defines the filename of the attachment by joining the strings
    after stripping and decoding a parameter.
    """
    filename_parts = []
    for param in dispositions[1:]:
        if param:
            name, value = decode_param(param)
            try:
                filename_parts = handle_split_filename(name, value, filename_parts)
            except Exception as err:
                logger.debug("Parse attachment name error: %s", err)
                filename_parts.insert(0, value)
    return filename_parts


def handle_split_filename(
    name: str, value: str, filename_parts: List[str]
) -> List[str]:
    """
    This function handles the split filename and
    inserts the value into given filename_parts using the index,
    also manages 'create-date'.
    """
    s_name = name.rstrip("*").split("*")
    if s_name[0] == "filename":
        index = 0 if len(s_name) <= 1 or s_name[1] == "" else int(s_name[1])
        filename_parts.insert(index, value[1:-1] if value.startswith('"') else value)

    if "create-date" in name:
        filename_parts["create-date"] = value

    return filename_parts


def str_decode_with_replacement(value: str, charset: str) -> str:
    """
    Encode and decode a string with a given character set, replacing any invalid characters

    Args:
        value (str): The string value to be encoded and decoded
        charset (str): The charset to use for encoding and decoding

    Returns:
        str: The resulting string after encoding and decoding with replacement of invalid characters
    """
    return str_decode(str_encode(value, charset, "replace"), charset)


def decode_param(param: str) -> Tuple[str, str]:
    """
    Decode the given parameter.

    Args:
        param (str): The parameter to decode, constructed in the form of "name=value".

    Returns:
        Tuple[str, str]: A tuple containing the name and the (possibly decoded) value.
    """
    name, values = split_params(param)
    v = "".join([decode_value(value) for value in values])
    logger.debug("Decoded parameter {} - {}".format(name, v))

    return name, v


def process_and_join_headers(headers, default_charset: str) -> str:
    """
    Process the decoded headers and join them into a single string.

    This function goes through each header, tries to decode it using its declared charset or the default charset
    and joins them into a single string.

    Args:
        headers (list): Decoded headers as a list of (text, charset) tuples.
        default_charset (str): The default encoding to be used if the charset can't be determined from the header.

    Returns:
        str: The joined headers as a single string.
    """
    for index, (text, charset) in enumerate(headers):
        headers[index] = get_decoded_header(index, text, charset, default_charset)

    return "".join(headers)

def split_params(param: str) -> Tuple[str, List[str]]:
    """
    Splits given parameters into name and values.

    Args:
         param (str): Parameter string.

    Returns:
        Tuple[str, List[str]]: A tuple containing the name and a list of values.

    """
    name, v = param.split("=", 1)
    values = v.split("\n")

    return name, values


def decode_value(value: str) -> str:
    """
    Decodes the given value if encoded.

    Args:
         value (str): Parameter value.

    Returns:
        str: The decoded value.
    """
    match = re.findall(r"=\?((?:\w|-)+)\?([QB])\?(.+?)\?=", value)
    value_results = []
    for encoding, type_, code in match:
        if type_ == "Q":
            value = quopri.decodestring(code)
        elif type_ == "B":
            value = code.encode()
            missing_padding = len(value) % 4
            if missing_padding:
                value += b"=" * (4 - missing_padding)
            value = base64.b64decode(value)
        value = str_encode(value, encoding)
        value_results.append(value)

    return "".join(value_results) if value_results else value


def get_decoded_header(index, text, charset: str, default_charset: str) -> str:
    """
    Get a decoded header in a safe way.

    This function attempts to decode a header using its declared charset or the default charset.
    If decoding fails due to an unknown charset, the default charset is forced.

    Args:
        index: The index of the header
        text: The text part of the header
        charset (str): The declared charset of the header
        default_charset (str): The default charset to use

    Returns:
        str: The decoded header
    """
    try:
        logger.debug(
            "Mail header no. {index}: {data} encoding {charset}".format(
                index=index,
                data=str_decode(text, charset or "utf-8", "replace"),
                charset=charset,
            )
        )
        return str_decode(text, charset or default_charset, "replace")
    except LookupError:
        # if the charset is unknown, force default
        return str_decode_with_replacement(text, default_charset)


def decode_content(message: Message) -> str:
    """Decode the content of an email message.

    This function decodes the content of an email message by inferring the character encoding
    and returning the decoded content as a string.

    Args:
        message: An email message object.

    Returns:
        The decoded content of the email message as a string.
    """

    def get_content_charset() -> str:
        """Get the character encoding of the email message.

        This function retrieves the character encoding from the email message.
        If the encoding is not defined, it defaults to 'utf-8'.

        Returns:
            The character encoding of the email message as a string.
        """
        charset = message.get_content_charset()
        return charset if charset else "utf-8"

    def decode_with_charset(content: bytes, charset: str) -> str:
        """Decode the content using the specified character encoding.

        This function decodes the given content using the specified character encoding
        and returns the decoded content as a string.

        Args:
            content: The content to be decoded.
            charset: The character encoding to be used for decoding.

        Returns:
            The decoded content as a string.
        """
        try:
            return content.decode(charset, "ignore")
        except LookupError:
            encoding = chardet.detect(content).get("encoding")
            if encoding:
                return content.decode(encoding, "ignore")
            return content

    content = message.get_payload(decode=True)
    charset = get_content_charset()

    return decode_with_charset(content, charset)


def fetch_email_by_uid(uid, connection, parser_policy):
    message, data = connection.uid('fetch', uid, '(BODY.PEEK[] FLAGS)')
    logger.debug("Fetched message for UID {}".format(int(uid)))

    raw_headers = data[0][0] + data[1]
    raw_email = data[0][1]

    email_object = parse_email(raw_email, policy=parser_policy)
    flags = parse_flags(raw_headers.decode())
    email_object.__dict__['flags'] = flags

    return email_object


def parse_flags(headers):
    """Copied from https://github.com/girishramnani/gmail/blob/master/gmail/message.py"""
    if len(headers) == 0:
        return []
    headers = bytes(headers, "ascii")
    return list(imaplib.ParseFlags(headers))
