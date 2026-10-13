import logging
from collections import defaultdict
from copy import copy
from email.utils import getaddresses
from smtplib import SMTP, SMTP_SSL, SMTPAuthenticationError, SMTPException, SMTPNotSupportedError, SMTPSenderRefused
import ssl
from typing import Dict
from socket import gaierror, timeout as timeout_exc
from time import sleep

from .utils import message_as_smtp_bytes
logger = logging.getLogger(__name__)

MAX_DELAY = 60  # cap of the exponential backoff between attempts, in seconds


class SMTPHandler:
    # cache of different smtp connections.
    # Usecase: user passes smtp server info in dict in a loop but we do want it connects just once
    _instances: Dict[str, SMTP] = {}

    def __init__(self, host="localhost", port=25, user=None, password=None, security=None, timeout=3, attempts=3,
                 delay=3, local_hostname=None):
        self.attempts = attempts
        # If sending fails, delay N seconds before another attempt, doubled with each further attempt.
        self.delay = delay

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
            self.local_hostname = local_hostname
        d = locals()
        del d["self"]
        self.key = repr(d)
        d["password"] = "********"
        self.obfuscated_key = repr(d)

    def connect(self):
        if self.instance:  # we received this instance as is so we suppose it is already connected
            return self.instance
        try:
            if self.security is None:
                self.security = defaultdict(
                    lambda: False, {587: "starttls", 465: "tls"})[self.port]

            context = ssl.create_default_context()
            if self.security == "tls":
                smtp = SMTP_SSL(self.host, self.port, self.local_hostname,
                                timeout=self.timeout, context=context)
            else:
                smtp = SMTP(self.host, self.port, self.local_hostname, timeout=self.timeout)
                if self.security == "starttls":
                    smtp.starttls(context=context)
            if self.user:
                try:
                    smtp.login(self.user, self.password)
                except SMTPAuthenticationError as e:
                    logger.error(
                        f"SMTP authentication failed: {self.obfuscated_key}.\n{e}")
                    return False
        except SMTPException as e:
            logger.error(f"SMTP connection failed: {self.obfuscated_key}.\n{e}")
            return False
        except (gaierror, ConnectionError):
            logger.error(f"SMTP connection refused: {self.obfuscated_key}.")
            return False
        return smtp

    @staticmethod
    def _send_message(smtp: SMTP, email, from_addr, to_addrs):
        """ Same as `smtp.send_message`, but flattens the message with our generator so that a GPG signature stays intact.
        (Envelope does not use the Resent-* headers so their handling is omitted.) """
        if from_addr is None:
            from_addr = getaddresses([email["Sender"] if "Sender" in email else email["From"]])[0][1]
        msg = copy(email)
        del msg["Bcc"]
        del msg["Resent-Bcc"]
        smtp.ehlo_or_helo_if_needed()  # needed for has_extn
        mail_options = ()
        policy = None
        try:
            "".join([from_addr, *to_addrs]).encode("ascii")
        except UnicodeEncodeError:
            if not smtp.has_extn("smtputf8"):
                raise SMTPNotSupportedError(
                    "One or more source or delivery addresses require"
                    " internationalized email support, but the server"
                    " does not advertise the required SMTPUTF8 capability")
            policy = email.policy.clone(utf8=True)
            mail_options = ("SMTPUTF8", "BODY=8BITMIME")
        return smtp.sendmail(from_addr, to_addrs, message_as_smtp_bytes(msg, policy), mail_options)

    def send_message(self, email, from_addr, to_addrs):
        for attempt in range(self.attempts):  # an attempt to reconnect possible
            try:
                if self.key not in self._instances:
                    smtp = self.connect()
                    if smtp is False:  # never cache a failed connection
                        return False
                    self._instances[self.key] = smtp
                smtp = self._instances[self.key]

                # recipients cannot be taken from headers when encrypting, we have to re-list them again
                return self._send_message(smtp, email, from_addr, to_addrs)
            except (timeout_exc, SMTPException) as e:
                # this connection is gone, reconnect next time
                if self.key in self._instances:
                    del self._instances[self.key]
                if isinstance(e, SMTPAuthenticationError):
                    logger.warning(
                        f"SMTP authentication error, will not re-try. {e}")
                    return False
                elif isinstance(e, timeout_exc):
                    if attempt + 1 < self.attempts:
                        self._backoff(attempt)
                    continue
                elif isinstance(e, SMTPException):
                    if attempt + 1 < self.attempts:
                        logger.info(
                            f"{type(e).__name__}, attempt {attempt + 1}. {e}")
                        self._backoff(attempt)
                        continue
                    else:
                        logger.warning(
                            f"{type(e).__name__}: sending failed. {e}")
                        return False
        logger.warning(f"SMTP sending timed out {self.attempts} times at {self.obfuscated_key}.")
        return False

    def _backoff(self, attempt):
        """ Sleep before another attempt: delay, 2×delay, 4×delay… capped at MAX_DELAY. """
        if self.delay:
            sleep(min(self.delay * 2 ** attempt, MAX_DELAY))

    @staticmethod
    def _quit(smtp):
        try:
            smtp.quit()
        except (SMTPException, OSError) as e:  # ex: the server has already closed the connection
            logger.debug(f"SMTP quit failed, connection dropped anyway. {e}")

    def quit(self):
        if self.key in self._instances:
            self._quit(self._instances.pop(self.key))

    @classmethod
    def quit_all(cls):
        instances = list(cls._instances.values())
        cls._instances.clear()
        [cls._quit(c) for c in instances]
