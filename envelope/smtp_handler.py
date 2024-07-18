import logging
from collections import defaultdict
from smtplib import SMTP, SMTP_SSL, SMTPAuthenticationError, SMTPException, SMTPSenderRefused
import ssl
from typing import Dict
from socket import gaierror, timeout as timeout_exc
from time import sleep
logger = logging.getLogger(__name__)


class SMTPHandler:
    # cache of different smtp connections.
    # Usecase: user passes smtp server info in dict in a loop but we do want it connects just once
    _instances: Dict[str, SMTP] = {}

    def __init__(self, host="localhost", port=25, user=None, password=None, security=None, timeout=3, attempts=3,
                 delay=3, local_hostname=None):
        self.attempts = attempts
        # If sending timeouts, delay N seconds before another attempt.
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
                        f"SMTP authentication failed: {self.key}.\n{e}")
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
                # this connection is gone, reconnect next time
                del self._instances[self.key]
                if isinstance(e, SMTPAuthenticationError):
                    logger.warning(
                        f"SMTP authentication error, will not re-try. {e}")
                    return False
                elif isinstance(e, timeout_exc):
                    if self.delay:
                        sleep(self.delay)
                    continue
                elif isinstance(e, SMTPException):
                    if attempt + 1 < self.attempts:
                        logger.info(
                            f"{type(e).__name__}, attempt {attempt + 1}. {e}")
                        if self.delay:
                            sleep(self.delay)
                        continue
                    else:
                        logger.warning(
                            f"{type(e).__name__}: sending failed. {e}")
                        return False

    def quit(self):
        if self.key in self._instances:
            self._instances[self.key].quit()

    @classmethod
    def quit_all(cls):
        [c.quit() for c in cls._instances.values()]
