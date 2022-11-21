import logging
import ssl
from collections import defaultdict
from email.utils import getaddresses, parseaddr
from io import TextIOBase, BufferedIOBase
from os import environ
from pathlib import Path
from smtplib import SMTP, SMTP_SSL, SMTPAuthenticationError, SMTPException, SMTPSenderRefused
from socket import gaierror, timeout as timeout_exc
from time import sleep
from typing import Optional, Tuple, Union, Dict, Type, Iterable

import magic

environ['PY3VE_IGNORE_UPDATER'] = '1'
from validate_email import validate_email  # noqa, #17 E402, the package name is py3-validate-email

logger = logging.getLogger(__name__)


class Address(str):
    """
        You can safely access the `self.name` property to access the real name and `self.address` to access the e-mail address.
        Example: Address("John <person@example.com>") -> self.name = "John", self.address = "person@example.com"
        
        Similarly, there are `self.user` and `self.host` properties.
        Example: -> self.user= "person", self.host = "example.com"

        All properties are guaranteed to be strings.
        Example: a = Address("") → a.name == "", bool(a) is False

        Address objects are equal if their e-mail address are equal. (Their real names might differ.)
        Address object is equal to a string if the string contains its e-mail address or the whole representation.
        Example: "person@example.com" == Address("John <person@example.com>") == "John <person@example.com>"  # True
        
        Method casefold returns casefolded object, useful for string comparing (whereas it is still equal to the original object).
        Example Address("John <person@example.com>").casefold() -> self.name == "john"

    """

    _name: str
    _address: str

    def __new__(cls, displayed_email=None, name=None, address=None):
        if displayed_email:
            v = parseaddr(displayed_email)
            name, address = v[0] or name, v[1] or address
        if name:
            displayed_email = f"{name} <{address}>"
        else:
            displayed_email = address
        instance = super().__new__(cls, displayed_email or "")
        instance._name, instance._address = name or "", address or ""
        return instance

    def __eq__(self, other):
        """
        Address objects are equal if their e-mail address are equal. (Their real names might differ.)
        Address object is equal to a string if the string contains its e-mail address or the whole representation.
        Example: "person@EXAMPLE.com" == Address("John <person@example.com>") == "John <person@example.com>"  # True
        """
        s = hash(other.casefold())
        return hash(self) == s or hash(str(self).casefold()) == s

    def casefold(self) -> "Address":
        """ When comparing Addresses, use casefolded version. Important for Address.__eq__
         (if retyped to a string, we could not compare addresses via Address.__hash__)"""
        return Address(str(self).casefold())

    def __hash__(self):
        """ E-mail addresses are case insensitive """
        return hash(self.address.casefold())

    def __repr__(self):
        return self.__str__()

    @property
    def name(self) -> str:
        return self._name

    @property
    def address(self) -> str:
        return self._address

    @property
    def host(self) -> str:
        """ XX Should it be part of Address.get? """
        try:
            return self._address.split("@")[1]
        except IndexError:
            return ""

    @property
    def user(self) -> str:
        """ XX Should it be part of Address.get? """
        try:
            return self._address.split("@")[0]
        except IndexError:
            return ""

    def get(self, name: bool = None, address: bool = None) -> str:
        """ Return `name` and/or `address`.
        Example:
            e = (Envelope()
                .to("person1@example.com")
                .to("person1@example.com, John <person2@example.com>")
                .to(["person3@example.com"]))

            [str(x) for x in e.to()]                # ["person1@example.com", "John <person2@example.com>", "person3@example.com"]
            [x.get(address=False) for x in e.to()]  # ["", "John", ""]
            [x.get(name=True) for x in e.to()]      # ["person1@example.com", "John", "person3@example.com"]
                                                    # return an address if no name given
            [x.get(address=True) for x in e.to()]   # ["person1@example.com", "person2@example.com", "person3@example.com"]
                                                    # addresses only
        """

        if not self:
            return ""
        if name is None and address is False:
            name = True
        elif name is False and address is None:
            address = True
        elif name is None and address is None:
            name = address = True

        if name and address:
            return str(self)
        if name and not address:
            s = self.name
            # 'John <person@example.com>' -> 'John'
            # 'person@example.com>' -> '' (address=False) or 'John' (name=True)
            if not s and address is not False:
                return self.address
            return s
        if not name and address:
            return self.address
        raise TypeError("Specify at least one of the `name` and `address` arguments.")

    @staticmethod
    def parse(email_or_list, single=False, allow_false=False):
        if allow_false and email_or_list is False:  # .from_(False), .sender(False)
            return False
        addresses = [Address(name=real_name, address=address) for real_name, address in
                     getaddresses(assure_list(email_or_list))
                     if not (real_name == address == "")]
        if single:
            if len(addresses) != 1:
                raise ValueError(f"Single e-mail address expected: {email_or_list}")
            return addresses[0]
        # if len(addresses) == 0:
        #     raise ValueError(f"E-mail address cannot be parsed: {email_or_list}")
        return addresses

    def is_valid(self, check_mx=False):
        if not validate_email(self.address, check_dns=False, check_smtp=False, check_blacklist=False):
            logger.warning(f"Address format invalid: '{self}'")
            return False
        elif check_mx and print(f"Verifying {self}...") and not validate_email(self.address, check_dns=True):
            logger.warning(f"MX check failed for: '{self}'")
            return False
        return True


class Attachment:

    def __init__(self, contents):
        """ get contents, user-defined name, user-defined mimetype and possibly True for being inline
        :type contents: data/Path [,mimetype] [,name] [,True for inline]
        """
        name = mimetype = inline = None
        if type(contents) is tuple:
            for s in contents[1:]:
                if not s:
                    continue
                elif s is True:
                    inline = True
                elif "/" in s:
                    mimetype = s
                else:
                    name = s
            if len(contents) == 4 and contents[3] and not inline:
                # (path, None, None, "cid.jpg") -> whereas name = "cid.jpg", inline is still not defined
                inline = True
            contents = contents[0]
        if not name and isinstance(contents, Path):
            name = contents.name
        if not name:
            name = "attachment.txt"

        try:
            data = assure_fetched(contents, bytes)
        except FileNotFoundError:
            logger.error(f"Could not fetch file {contents.absolute()}")
            raise
        if not mimetype:
            if isinstance(contents, Path):
                mimetype = get_mimetype(path=contents)
            else:
                mimetype = get_mimetype(data=data)            

        self.data: bytes = data
        self.mimetype = mimetype
        self.name = name
        self.inline = inline

    def __repr__(self):
        l = [self.name, self.mimetype, self.get_sample()]
        if self.inline:
            l.append("inline=True")
        return f"Attachment({', '.join(l)})"

    def __str__(self):
        return str(self.data, "utf-8")

    def __bytes__(self):
        return self.data

    def get_sample(self):
        if self.data is None:
            raise ValueError(f"Empty attachment {self.name}")
        sample = self.data.decode("utf-8", "ignore").replace("\n", " ").replace("\r", " ")
        if len(sample) > 24:
            sample = sample[:20].strip() + "..."
        return sample

    def preview(self):
        if self.inline:
            return f"{self.name} ({self.mimetype}): <img src='cid:{self.inline}'/>"
        else:
            return f"{self.name} ({self.mimetype}): {self.get_sample()}"


class AutoSubmittedHeader:
    """  "auto-replied": direct response to another message by an automatic process """

    def __init__(self, parent: 'Envelope'):
        self._parent = parent

    def __call__(self, val="auto-replied"):
        """
        :param val: "auto-replied": direct response to another message by an automatic process
        """
        self._parent.header("Auto-Submitted", val, replace=True)
        return self._parent

    def no(self):
        """ message was originated by a human """
        return self("no")

    def auto_replied(self):
        """ direct response to another message by an automatic process """
        return self()

    def auto_generated(self):
        """ automatic (often periodic) processes (such as UNIX "cron jobs") which are not direct responses to other messages """
        return self("auto-generated")


class _Message:
    auto: Optional[bytes] = None
    plain: Optional[bytes] = None
    html: Optional[bytes] = None
    boundary: Optional[str] = None  # you may specify e-mail boundary used when multiple alternatives present

    def _decode(self, val, mime_alternative):
        try:
            val = val.decode()
        except UnicodeDecodeError as e:
            logger.warning(f"Cannot decode the message correctly,"
                           f" {mime_alternative} alternative bytes are not in Unicode.")
            val = str(val)
        return val

    def get(self, type_: Union[Type[bytes], Type[str]] = bytes) -> Tuple[Union[bytes, str, None], Union[bytes, str, None]]:
        """
        :param type_: Set to str if we should return str instead of bytes.
         Note it raises a warning if bytes were not in Unicode.
        :return (plain, html) tuple Data assured to be fetched. Raises if there is anything left in `auto`.
        """
        i = iter((self.auto,))
        plain, html = self.plain or next(i, None), self.html or next(i, None)
        if next(i, False):
            raise ValueError("Specified all of message alternative=plain, alternative=html and alternative=auto,"
                             " choose only two.")

        # XX As of Python3.10 replace with longer but more readable:
        # plain, html = self.plain, self.html
        # if self.auto:
            # match bool(plain), bool(html):
            #     case False, _:
            #         plain = auto
            #     case _, False:
            #         html = auto
            #     case _:
        #             raise ValueError("Specified all of message alternative=plain, alternative=html and alternative=auto,"
        #                      " choose only two.")


        if type_ is str:
            if plain:
                plain = self._decode(plain, "plain")
            if html:
                html = self._decode(html, "html")
        return plain, html

    def is_empty(self):
        return tuple(self.get()) == (None, None)

    def __str__(self):
        text, html = self.get(str)
        if text and html:
            return " ".join(("(text/plain)", text, "(text/html)", html))
        else:
            return text or html


class SMTPHandler:
    # cache of different smtp connections.
    # Usecase: user passes smtp server info in dict in a loop but we do want it connects just once
    _instances: Dict[str, SMTP] = {}

    def __init__(self, host="localhost", port=25, user=None, password=None, security=None, timeout=3, attempts=3,
                 delay=3):
        self.attempts = attempts
        self.delay = delay  # If sending timeouts, delay N seconds before another attempt.

        if isinstance(host, SMTP):
            self.instance = host
        else:
            self.instance = None
            self.host = host
            self.port = int(port)
            self.user = user
            self.password = password
            self.security = security
            self.timeout = timeout
        d = locals()
        del d["self"]
        self.key = repr(d)

    def connect(self):
        if self.instance:  # we received this instance as is so we suppose it is already connected
            return self.instance
        try:
            if self.security is None:
                self.security = defaultdict(lambda: False, {587: "starttls", 465: "tls"})[self.port]

            context = ssl.create_default_context()
            if self.security == "tls":
                smtp = SMTP_SSL(self.host, self.port, timeout=self.timeout, context=context)
            else:
                smtp = SMTP(self.host, self.port, timeout=self.timeout)
                if self.security == "starttls":
                    smtp.starttls(context=context)
            if self.user:
                try:
                    smtp.login(self.user, self.password)
                except SMTPAuthenticationError as e:
                    logger.error(f"SMTP authentication failed: {self.key}.\n{e}")
                    return False
        except SMTPException as e:
            logger.error(f"SMTP connection failed: {self.key}.\n{e}")
            return False
        except (gaierror, ConnectionError):
            logger.error(f"SMTP connection refused: {self.key}.")
            return False
        return smtp

    def send_message(self, email, from_addr, to_addrs):
        for attempt in range(self.attempts):  # an attempt to reconnect possible
            try:
                if self.key not in self._instances:
                    self._instances[self.key] = self.connect()
                smtp = self._instances[self.key]
                if smtp is False:
                    return False

                # recipients cannot be taken from headers when encrypting, we have to re-list them again
                return smtp.send_message(email, from_addr=from_addr, to_addrs=to_addrs)
            except (timeout_exc, SMTPException) as e:
                del self._instances[self.key]  # this connection is gone, reconnect next time
                if isinstance(e, SMTPSenderRefused):
                    logger.warning(f"SMTP sender refused, unable to reconnect. {e}")
                    return False
                elif isinstance(e, timeout_exc):
                    if self.delay:
                        sleep(self.delay)
                    continue
                elif isinstance(e, SMTPException):
                    if attempt + 1 < self.attempts:
                        logger.info(f"{type(e).__name__}, attempt {attempt + 1}. {e}")
                        if self.delay:
                            sleep(self.delay)
                        continue
                    else:
                        logger.warning(f"{type(e).__name__}: sending failed. {e}")
                        return False

    def quit(self):
        if self.key in self._instances:
            self._instances[self.key].quit()

    @classmethod
    def quit_all(cls):
        [c.quit() for c in cls._instances.values()]


def is_gpg_importable_key(key):
    """ Check if the variable contains the key contents itself
     (it may contain a fingerprint or an e-mail address too) """
    return len(key) >= 512  # 512 is the smallest possible GPG key


def get_mimetype(data:bytes=None, path:Path=None):
    """ We support both python-magic and file-magic library, any of them can be on the system. #25
        Their funcionality is the same, their API differs.
    """
    # XX change to match statement as of Python3.10
    if hasattr(magic.Magic, "from_file"):  # this is python-magic
        if data:
            return magic.Magic(mime=True).from_buffer(data)
        if path:
            return magic.Magic(mime=True).from_file(str(path))
    else:  # this is file-magic
        if data:
            return magic.detect_from_content(data).mime_type
        if path:
            return magic.detect_from_filename(str(path)).mime_type

def assure_list(v):
    """ Accepts object and returns list.
    If object is tuple, generator, set, frozenset, it's converted to a list.
    If object is not a list, it's appended to a list.
    If None, returns an empty list.
        "test" → ["test"]
        (5,1) → [5,1]
        ["test", "foo"] → ["test", "foo"]
    """
    if v is None:
        return []
    if isinstance(v, Iterable) and not isinstance(v, (TextIOBase, BufferedIOBase, str, bytes)):
        return list(v)
    return [v]


def assure_fetched(message, retyped=None):
    """ Accepts object, returns its string or bytes.
    If object is
        * str or bytes, we consider this is the file contents
        * Path, we load the file
        * stream, we read it
        * bool or none, it is returned as is.
    :type message: object to be converted
    :type retyped: * str or bytes to assure str/bytes are returned.
                   * None does not perform retyping.
    """
    if message is None:
        return None
    elif isinstance(message, Path):
        message = message.read_bytes()
    elif isinstance(message, (TextIOBase, BufferedIOBase)):
        message = message.read()
    elif not isinstance(message, (str, bytes, bool)):
        raise ValueError(f"Expected str, bytes, stream or pathlib.Path: {message}")

    if retyped is bytes and isinstance(message, str):
        message = message.encode("utf-8")
    elif retyped is str and isinstance(message, bytes):
        message = message.decode("utf-8")
    return message
