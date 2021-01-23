import io
import logging
import smtplib
from collections import defaultdict
from email.utils import getaddresses, parseaddr
from pathlib import Path
from socket import gaierror, timeout

import magic
from validate_email import validate_email  # package py3-validate-email

logger = logging.getLogger(__name__)


class Address(str):
    """
        You can safely access the `self.name` property to access the real name and `self.address` to access the e-mail address.
        Example: Address("John <person@example.com>") -> self.name = "John", self.address = "person@example.com"

        Address objects are equal if their e-mail address are equal. (Their real names might differ.)
        Address object is equal to a string if the string contains its e-mail address or the whole representation.
        Example: "person@example.com" == Address("John <person@example.com>") == "John <person@example.com>"  # True

    """

    def __new__(cls, displayed_email=None, name=None, address=None):
        if displayed_email:
            v = parseaddr(displayed_email)
            name, address = v[0] or name, v[1] or address
        if name:
            displayed_email = f"{name} <{address}>"
        else:
            displayed_email = address
        instance = super().__new__(cls, displayed_email)
        instance._name, instance._address = name, address
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
    def name(self):
        return self._name

    @property
    def address(self):
        return self._address

    @property
    def host(self):
        """ XX Should it be part of Address.get? """
        try:
            return self._address.split("@")[1]
        except IndexError:
            return None

    @property
    def user(self):
        """ XX docuemnt Should it be part of Address.get? """
        try:
            return self._address.split("@")[0]
        except IndexError:
            return None

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
        addresses = [Address(name=real_name, address=address) for real_name, address in getaddresses(assure_list(email_or_list))
                     if not (real_name == address == "")]
        if single:
            if len(addresses) != 1:
                raise ValueError(f"Single e-mail address expected: {email_or_list}")
            return addresses[0]
        if len(addresses) == 0:
            raise ValueError(f"E-mail address cannot be parsed: {email_or_list}")
        return addresses

    def is_valid(self, check_mx=False):
        if not validate_email(self.address, check_mx=False):
            logger.warning(f"Address format invalid: '{self}'")
            return False
        elif check_mx and print(f"Verifying {self}...") and not validate_email(self.address, check_mx=True):
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
            m = magic.Magic(mime=True)
            mimetype = m.from_file(str(contents)) if isinstance(contents, Path) else m.from_buffer(contents)

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
    auto: bytes = None
    plain: bytes = None
    html: bytes = None
    boundary: str = None  # you may specify e-mail boundary used when multiple alternatives present

    def get(self) -> (str, str):
        """
            :return text, html generator they are assured to be fetched. Raises is there is anything left in `auto`.
        """
        i = iter((self.auto,))
        ret = self.plain or next(i, None), self.html or next(i, None)
        if next(i, False):
            raise ValueError("Specified all of message alternative=plain, alternative=html and alternative=auto,"
                             " choose only two.")
        return ret

    def is_empty(self):
        return tuple(self.get()) == (None, None)

    def __str__(self):
        text, html = self.get()
        if text and html:
            return " ".join(("(text/plain)", text, "(text/html)", html))
        else:
            return text or html


class SMTP:
    # cache of different smtp connections.
    # Usecase: user passes smtp server info in dict in a loop but we do want it connects just once
    _instances = {}

    def __init__(self, host="localhost", port=25, user=None, password=None, security=None):
        if isinstance(host, smtplib.SMTP):
            self.instance = host
        else:
            self.instance = None
            self.host = host
            self.port = int(port)
            self.user = user
            self.password = password
            self.security = security
        d = locals()
        del d["self"]
        self.key = repr(d)

    def connect(self):
        if self.instance:  # we received this instance as is so we suppose it is already connected
            return self.instance
        try:
            if self.security is None:
                self.security = defaultdict(lambda: False, {587: "starttls", 465: "tls"})[self.port]

            if self.security == "tls":
                smtp = smtplib.SMTP_SSL(self.host, self.port, timeout=1)
            else:
                smtp = smtplib.SMTP(self.host, self.port, timeout=1)
                if self.security == "starttls":
                    smtp.starttls()
            if self.user:
                try:
                    smtp.login(self.user, self.password)
                except smtplib.SMTPAuthenticationError as e:
                    logger.error(f"SMTP authentication failed: {self.key}.\n{e}")
                    return False
        except smtplib.SMTPException as e:
            logger.error(f"SMTP connection failed: {self.key}.\n{e}")
            return False
        except (gaierror, ConnectionError):
            logger.error(f"SMTP connection refused: {self.key}.")
            return False
        return smtp

    def send_message(self, email, to_addrs):
        for attempt in range(1, 3):  # an attempt to reconnect possible
            try:
                if self.key not in self._instances:
                    self._instances[self.key] = self.connect()
                smtp = self._instances[self.key]
                if smtp is False:
                    return False

                # recipients cannot be taken from headers when encrypting, we have to re-list them again
                return smtp.send_message(email, to_addrs=to_addrs)

            except (timeout, smtplib.SMTPSenderRefused) as e:  # timeouts
                if attempt == 2:
                    logger.warning(f"SMTP sender refused, unable to reconnect.\n{e}")
                    return False
                del self._instances[self.key]  # this connection is gone possibly due to a timeout, reconnect
                continue
            except smtplib.SMTPException as e:
                logger.error(f"SMTP sending failed.\n{e}")
                return False


def is_gpg_fingerprint(key):
    """ Check if we have key fingerprint in the variable or the key contents itself """
    return isinstance(key, str) and len(key) * 4 < 512  # 512 is the smallest possible GPG key


def assure_list(l):
    """ Accepts object and returns list, if object is not list, it's appended to a list. If None, returns empty list.
        "test" → ["test"]
        (5,1) → [(5,1)]
        ["test", "foo"] → ["test", "foo"]
    """
    if l is None:
        return []
    elif type(l) is not list:
        return [l]
    return l


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
    elif isinstance(message, (io.TextIOBase, io.BufferedIOBase)):
        message = message.read()
    elif type(message) not in [str, bytes, bool]:
        raise ValueError(f"Expected str, bytes, stream or pathlib.Path: {message}")

    if retyped is bytes and type(message) is str:
        message = message.encode("utf-8")
    elif retyped is str and type(message) is bytes:
        message = message.decode("utf-8")
    return message
