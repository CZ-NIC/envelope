"""Delivery methods of `Envelope`: SMTP/sendmail configuration, `send`, `check`, `smtp_quit` and the actual sending.
Mixin: shares one `self` with `Envelope`; nothing here is meant to be used standalone.
"""
import logging
import smtplib
import subprocess
import sys
from configparser import ConfigParser
from email.utils import make_msgid, formatdate
from os import environ
from pathlib import Path
from typing import Any

from ._auth import AuthResult
from .constants import SIMULATION, SAFE_LOCALE, SENDMAIL_PATH
from .smtp_handler import SMTPHandler
from .utils import is_safe_argv_value, message_as_string

logger = logging.getLogger("envelope.envelope")  # same logger name as before the split


class _DeliveryMixin:
    def smtp(self, host: Any = "localhost", port=25, user=None, password=None, security=None, timeout=3, attempts=3,
             delay=3, local_hostname=None):
        """
        Obtain SMTP server connection.
        Note that you may safely call this in a loop,
            envelope will remember the settings and connect only once (without reconnecting every iteration).
        :param host: hostname, smtplib.SMTP, INI file path, False, or a list or dict with the parameters (see README.md)
        :param port:
        :param user:
        :param password:
        :param security: If not set, automatically set to `starttls` for port *587* and to `tls` for port *465*
        :param timeout: How many seconds should SMTP wait before timing out.
        :param attempts: How many times we try to send the message to an SMTP server.
        :param delay: How many seconds to sleep before re-trying a failed connection, doubled with every further attempt (at most 60 s).
        :param local_hostname: FQDN of the local host in the HELO/EHLO command.
        :return:
        """
        # CLI interface returns always a list or dict, ex: host=["localhost"] or host=["ini file"] or host={}
        # module one-liner interface fills host param, ex: host="localhost", host="ini file", host={"port": 123}, ["localhost", 123]
        # fluent interface fills all locals, ex: {"host": "ini file", "port": default 25}
        # check for the presence of an INI file
        ini = None
        if type(host) is str:
            ini = host
        elif type(host) is list and len(host) > 0:
            ini = host[0]
        elif type(host) is dict and "host" in host:
            ini = host["host"]

        if ini and ini.endswith("ini"):
            if not Path(ini).exists() and not Path(ini).is_absolute():
                # when imported as a library, the relative path to the ini file might point to the main program directory
                ini = Path(Path(sys.argv[0]).parent, ini)

            if Path(ini).exists():  # existing INI file
                config = ConfigParser()
                config.read(ini)
                try:
                    host = {k: v for k, v in config["SMTP"].items()}
                except KeyError as e:
                    raise FileNotFoundError(f"INI file {ini} exists but section [SMTP] is missing") from e

        if type(host) is dict:  # ex: {"host": "localhost", "port": 1234}
            self._smtp = SMTPHandler(**host)
        elif type(host) is list:  # ex: ["localhost", 1234]
            self._smtp = SMTPHandler(*host)
        elif isinstance(host, smtplib.SMTP):
            self._smtp = SMTPHandler(host)
        elif host == False:
            self._smtp = False
            self._sendmail = True
        else:
            self._smtp = SMTPHandler(host, port, user, password, security, timeout=timeout, attempts=attempts,
                                     delay=delay, local_hostname=local_hostname)
        return self

    def sendmail(self, sendmail=True):
        """
        :param sendmail: String for Sendmail binary or True.
        Disables SMTP when enabled.
        """
        self._sendmail = sendmail
        if bool(self._sendmail):
            self._smtp = False
        return self

    def send(self, send=True, sign=None, encrypt=None):
        """
        Send e-mail contents. To check e-mail was successfully sent, cast the returned object to bool.
        :param send: True to send now, False to print debug information.
        :param sign: Turn signing on.
            The parameter will be passed as the `key` parameter of the .signature method.
            * GPG: Ex: True or default signing key ID/fingerprint.
            * S/MIME: Any attainable contents having the key + signing certificate combined in a single file.
              (If not in a single file, use the full .signature() method instead.)
        :param encrypt: Turn encrypting on.
            The parameter will be passed as the `key` parameter of the .encryption method.
            Ex: Any attainable contents with recipient GPG public key or S/MIME certificate to be encrypted with.
        :return:
        """
        if self._processed:
            raise RuntimeError("Cannot call .send() after .sign()/.encrypt()."
                               " You probably wanted to use .signature()/.encryption() instead.")
        self._start(sign=sign, encrypt=encrypt, send=send)
        return self

    def _send_now(self, email, encrypt, encrypted_subject, send):
        try:
            if not self._from and self._from is not False and send is True:
                # allow ignoring the `From` header when deliberately set to False
                logger.error("You have to specify From e-mail.")
                return False
            if self._from:
                email["From"] = str(self._from)
            if self._to:
                email["To"] = ",".join(map(str, self._to))
            if self._cc:
                email["Cc"] = ",".join(map(str, self._cc))
            if self._reply_to:
                email["Reply-To"] = ",".join(map(str, self._reply_to))
        except IndexError as e:
            s = set(self._to + self._cc + self._bcc + self._reply_to + [x for x in [self._from] if x])
            logger.error(f"An e-mail address seem to be malformed.\nAll addresses: {s}\n{e}")
            return False

        # insert arbitrary headers
        # XX do not we want to encrypt these headers with GPG/SMIME?
        for k, v in self._headers.items():
            if k.lower() in ("content-type", "content-transfer-encoding", "mime-version"):
                # skip headers already inserted in _prepare_email
                continue
            try:
                email[k] = v
            except TypeError:
                # ex: Using random string with header Date
                raise TypeError(f"Wrong header {k} value: {v}")
        if "Date" not in email and not self._ignore_date:
            email["Date"] = formatdate(localtime=True)
        if "Message-ID" not in email and send != SIMULATION:  # we omit this field when testing
            email["Message-ID"] = make_msgid()

        if send and send != SIMULATION:
            recipients = list(map(str, set(self._to + self._cc + self._bcc)))
            # `_deliver_now` returns the failed recipients (an empty container on full success) or False on error
            if self._deliver_now(email, recipients) is False:
                return False
        else:
            if send != SIMULATION:
                self._result.append(f"{'*' * 100}\nHave not been sent from {(self._from_addr or self._from or '-')}"
                                    f" to {', '.join(self.recipients()) or '-'}")
            if encrypt:
                if encrypted_subject:
                    self._result.append(f"Encrypted subject: {self._subject}")
                self._result.append(f"Encrypted message: {self._message}")
            if len(self._result):  # put an empty line only if some important content was already placed
                self._result.append("")

        return email

    def _deliver_now(self, email, recipients):
        # _smtp XOR _sendmail
        if (_smtp := bool(self._smtp)) == (_sendmail := bool(self._sendmail)):
            logger.error(f"Need either SMTP (is {('off', 'on')[_smtp]}) or local delivery/sendmail (is {('off', 'on')[_sendmail]}) to send")
            return False
        if self._smtp:
            success_or_failures = self._deliver_smtp(email, self._from_addr, recipients)
        elif self._sendmail:
            success_or_failures = self._deliver_sendmail(email, self._from_addr or self._from, recipients)
        else:
            assert False, "Should not reach, either SMTP or Sendmail should work"

        if success_or_failures:
            logger.warning(f"Unable to send to all recipients: {repr(success_or_failures)}.")
        # elif success_or_failures is False:
        #     # TODO add here and test, logger.warning(f"Sending {recipients}, Message-ID: {email["Message-ID"]}")
        #     return False
        return success_or_failures

    def _deliver_smtp(self, email, from_addr, recipients):
        """
        Use configured SMTP server to deliver email.
        :param email: String contents of whole email to send
        :param from_addr: Email address of sender
        :param recipients: List of recipient email addresses
        :returns: List of recipients to whom delivery failed.
            Or False for an unspecified error condition
        :rtype: list or False
        """
        if not isinstance(self._smtp, SMTPHandler):
            self._smtp = SMTPHandler()
        return self._smtp.send_message(email, from_addr=self._from_addr, to_addrs=recipients)

    def _deliver_sendmail(self, email, from_addr, to_addrs):
        """
        Use a  local MTA with sendmail interface to send mail via queue"

        :param email: String contents of whole email to send
        :param from_addr: Email address of sender
        :param recipients: (unused, for signature compatibility with _deliver_smtp,
            Originally: List of recipient email addresses)
        :returns: Empty list on success or False for an unspecified error condition
            (For return compatibilty with _deliver_smtp)
        :rtype: list or False
        """
        self._sendmail = SENDMAIL_PATH if self._sendmail == True  else str(self._sendmail)
        _unused = to_addrs
        from_addr = str(from_addr)
        if not is_safe_argv_value(from_addr):
            logger.error(f"Refusing to invoke sendmail with a suspicious From address: {from_addr!r}")
            return False
        args = [self._sendmail, "-t", "-oi", "-f", from_addr]
        try:
            subprocess.run(args, input=message_as_string(email), text=True, check=True)
            return []
        except subprocess.CalledProcessError:
            return False

    def check(self, check_mx=True, check_smtp=True) -> bool:
        """
        If sender specified, check if DMARC DNS records exist and prints out the information.
        :param check_mx: bool If True, all e-mail addresses are checked for MX record.
        :param check_smtp: bool If True, we try to connect to the SMTP host.
        :rtype: bool All e-mail addresses are valid and SMTP connection worked
        """
        passed = all(address.is_valid(check_mx)
                     for address in self._to + self._cc + self._bcc + self._reply_to + [x for x in [self._from] if x])

        if self._from:
            try:
                domain = self._from.address.split("@")[1]
            except IndexError:
                passed = False
                logger.warning(f"Could not parse domain from the From address '{self._from}'")
            else:
                def dig(query_or_list, rr="TXT"):
                    if type(query_or_list) is not list:
                        query_or_list = [query_or_list]
                    for query in query_or_list:
                        if not is_safe_argv_value(query):
                            logger.warning(f"Refusing to run dig with a suspicious query: {query!r}")
                            return []
                        try:
                            text = subprocess.check_output(["dig", "-t", rr, query],
                                                           env=dict(environ, LC_ALL=SAFE_LOCALE)).decode("utf-8")
                            text = text[text.find("ANSWER SECTION:"):]
                            text = text[:text.find(";;")].split("\n")[1:-2]
                            res = []
                            for line in text:
                                # Strip tabs and quotes `_dmarc.gmail.com.\t600\tIN\tTXT\t"v=DMARC1;"` → `v=DMARC1;`
                                res.append(line.split("\t")[-1][1:-1])  #
                        except IndexError:
                            return []
                        else:
                            if res:
                                return res

                def search_start(list_, needle):
                    if list_:
                        for line in list_:
                            if line.startswith(needle):
                                return line

                spf = search_start(dig(domain), "v=spf")
                if not spf:
                    spf = search_start(dig(domain, "SPF"), "v=spf")
                if spf:
                    print(f"SPF found on the domain {domain}: {spf}")
                else:
                    logger.warning(f"SPF not found on the domain {domain}")
                print(f"See: dig -t SPF {domain} && dig -t TXT {domain}")

                dkim = dig(["mx1._domainkey." + domain, "mx._domainkey." + domain, "default._domainkey." + domain])
                if dkim:
                    print(f"DKIM found: {dkim}")
                else:
                    print("Could not spot DKIM. (But I do not know the selector.)")

                dmarc = dig("_dmarc." + domain)
                if dmarc:
                    print(f"DMARC found: {dmarc}")
                else:
                    print("Could not spot DMARC.")

        if check_smtp:
            print("Trying to connect to the SMTP...")
            passed *= bool(self._smtp.connect())  # check SMTP
        return passed

    def _check_auth(self):
        """ Experimental. """
        # NOTE Do not know how to map in API. Because .check() seems to be for sending and this one for receiving.
        return AuthResult.from_headers(self._headers)

    def smtp_quit(self=None):
        """ Explicitly closes cached SMTP connections. Either class or instance can be called.
        Envelope.smtp_quit() → closing all
        Envelope().smtp_quit() → closing only those which match the SMTP server provided to the Envelope object
        """
        if self is None:
            SMTPHandler.quit_all()
        else:
            self._smtp.quit()
