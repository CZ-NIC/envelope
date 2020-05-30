import io
import logging
import smtplib
from collections import defaultdict
from pathlib import Path
from socket import gaierror

logger = logging.getLogger(__name__)


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
            # smtp = self._smtp
            # if not smtp:
            #     logger.error("No SMTP given")
            #     return False
            # key = repr(smtp)
            try:
                if self.key not in self._instances:
                    self._instances[self.key] = self.connect()
                smtp = self._instances[self.key]
                if smtp is False:
                    return False

                # recipients cannot be taken from headers when encrypting, we have to re-list them again
                return smtp.send_message(email, to_addrs=to_addrs)

            except smtplib.SMTPSenderRefused as e:  # timeout
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


def assure_fetched(message, retyped=str):
    """ Accepts object, returns its string or bytes.
    If object is
        * stream or bytes, we consider this is the file contents
        * Path, we load the file
        * bool or none, it is returned as is.
    :type message: object to be converted
    :type retyped: str or bytes to assure str/bytes are returned
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
