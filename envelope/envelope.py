#!/usr/bin/env python3

import argparse
import io
import logging
import smtplib
import subprocess
import sys
import tempfile
import warnings
from collections import defaultdict
from configparser import ConfigParser
from copy import copy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import make_msgid, formatdate, getaddresses
from getpass import getpass
from pathlib import Path
from socket import gaierror
from typing import Union

try:
    import gnupg
except ImportError:
    gnupg = None
try:
    import smime
except ImportError:
    smime = None
import magic
from jsonpickle import decode

__doc__ = """


Quick layer python-gnupg, smime, smtplib and email handling packages.
Their common usecases merged into a single function. Want to sign a text and tired of forgetting how to do it right?
You do not need to know everything about GPG or S/MIME, you do not have to bother with importing keys.
Do not hassle with reconnecting SMTP server. Do not study various headers meanings to let your users unsubscribe via a URL.
You insert a message and attachments and receive signed and/or encrypted output to the file or to your recipients' e-mail. 
Just single line of code. With the great help of the examples below.

Usage:
  * launch as application, see ./envelope.py --help
  * import as a module to your application, ex: `from envelope import envelope` 

Example:

gpg(message="Hello world",
        output="/tmp/output_file",
        encrypt_file="/tmp/remote_key.asc",
        sender="me@email.com",
        to="remote_person@example.com")
"""

logger = logging.getLogger(__name__)
_cli_invoked = False


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


class AutoSubmittedHeader:
    """  "auto-replied": direct response to another message by an automatic process """

    def __init__(self, parent: 'Envelope'):
        self._parent = parent

    def __call__(self, val="auto-replied"):
        """
        :param val: "auto-replied": direct response to another message by an automatic process
        """
        self._parent.header("Auto-Submitted", val)
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

    # def __init__(self):
    #     self.instance = self.host = self.port = self.user = self.password = self.security = None

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


class Envelope:
    default: 'Envelope'

    _encrypts_cache = {}  # cache
    _gnupg: gnupg.GPG

    def __bool__(self):
        return self._status

    def __str__(self):
        if not self._result:
            if self._encrypt or self._sign:
                self._start()
            else:
                print("Nothing to do, let's assume this is a bone of an e-mail message "
                      "by appending `--send False` flag to produce an output.\n")
                self._start(send=False)
        return self._get_result()

    def __bytes__(self):
        return assure_fetched(self._get_result(), bytes)

    def __eq__(self, other):
        if type(other) in [str, bytes]:
            return assure_fetched(self._get_result(), bytes) == assure_fetched(other, bytes)

    def _get_result(self):
        """ concatenate output string """
        s = "\n".join(self._result)
        self._result = [s]  # slightly quicker next time if ever containing a huge amount of lines
        return s

    def __init__(self, message=None, output=None, gpg=None, smime=None, headers=None,
                 sign=None, passphrase=None, attach_key=None, cert=None,
                 encrypt=None, to=None, sender=None,
                 subject=None, cc=None, bcc=None, reply_to=None, attachments=None,
                 smtp=None, send=None):
        """
        :rtype: object If output not set, return output bytes, else True/False if output file was correctly written to.

        Any fetchable contents means plain text, bytes or stream (ex: from open()).
        In *module interface*, you may use Path object to the file.
        In *CLI interface*, additional flags are provided.

        Input / Output
        :param message: Any fetchable contents.
        :param output: Path to file to be written to (else the contents is returned).
        :param gpg: Home folder of GNUPG rings else default ~/.gnupg is used. Put True for prefer GPG over SMIME.

        Signing
        :param sign: True or key id if the message is to be signed. S/MIME certificate key or Path or stream (ex: from open()).
        :param passphrase: If signing key needs passphrase.
        :param attach_key: If True, public key is appended as an attachment.
        :param cert: S/MIME certificate contents or Path or stream (ex: from open()) if certificate not included in the key.

        Encrypting
        :param encrypt: Recipients public key string or Path or stream (ex: from open()).
        :param to: E-mail or list. If encrypting used so that we choose the key they will be able to decipher with.
        :param sender: E-mail. If encrypting used so that we choose our key to be still able to decipher the message later with.
                        If False, we explicitly declare to give up on deciphering later.

        Sending
        :param subject: E-mail subject
        :param reply_to: Reply to header
        :param smtp: tuple or dict of these optional parameters: host, port, username, password, security ("tlsstart").
            Or link to existing INI file with the SMTP section.
        :param send: True for sending the mail. False will just print the output.
        :param cc: E-mail or their list.
        :param bcc: E-mail or their list.
        :param attachments: Attachment or their list. Attachment is defined by file path or stream (ex: from open()),
            optionally in tuple with the file name in the e-mail and/or mimetype.
        :param headers: List of headers which are tuples of name, value. Ex: [("X-Mailer", "my-cool-application"), ...]
        """
        self._message = None
        self._output = None
        self._gpg: Union[str, bool] = None
        self._sign = None
        self._passphrase = None
        self._attach_key = None
        self._cert = None
        self._encrypt = None
        self._to = []
        self._sender = None
        self._cc = []
        self._bcc = []
        self._subject = None
        self._smtp = None
        self._attachments = []
        self._reply_to = None
        self._headers = {}

        self._status = False  # whether we successfully encrypted/signed/send
        self._processed = False  # prevent the user from mistakenly call .sign().send() instead of .signature().send()
        self._result = []  # text output for str() conversion
        self._smtp = SMTP()
        self.auto_submitted = AutoSubmittedHeader(self)  # allows fluent interface to set header

        # if a parameter is not set, use class defaults, else init with parameter
        for k, v in locals().items():
            if k in ["self", "send"]:
                continue
            elif k == "smime":  # smime uses _gpg, not _smime because it needs no parameter
                if v is True:
                    self.smime()
            elif v is None:
                if hasattr(self, "default"):
                    v = copy(getattr(self.default, "_" + k))  # ex `v = copy(self.default._message)`
            elif k == "passphrase":
                self.signature(passphrase=v)
            elif k == "attach_key":
                if v is True:
                    self.signature(attach_key=v)
            elif k == "cert":
                self.signature(None, cert=v)
            elif k == "to":
                self.to(v)
            elif k == "attachments":
                self.attach(v)
            elif k == "headers":  # [(header-name, val), ...]
                for it in v:
                    self.header(*it)
            elif k == "sign":
                self.signature(v)
            elif k == "encrypt":
                self.encryption(v)
            elif v is not None:
                getattr(self, k)(v)  # ex: self.message(message)

        if sign or encrypt or send is not None:
            self._start(sign=sign, encrypt=encrypt, send=send)

    def cc(self, email_or_list):
        self._cc += assure_list(email_or_list)
        return self

    def bcc(self, email_or_list):
        self._bcc += assure_list(email_or_list)
        return self

    def message(self, text=None, *, path=None):
        if path:
            text = Path(path)
        self._message = assure_fetched(text, bytes)
        return self

    def reply_to(self, email):
        self._reply_to = email
        return self

    def sender(self, email):
        # XXX since sender is a real header, we should somehow distinguish 'sender' from 'from'. Pity that 'from' is a reserved keyword, from_ looks bad. Keyword header:Literal["from", "sender"]="from"?
        # Is there a usecase Sender is useful to be set?
        # def envelope(**kw): l(**{"from": "me@example.com", "subject": "my e-mail"}) Or make 'from' at least possible?
        # Or method from_to?
        self._sender = email
        return self

    def from_(self, email):
        """ An alias to self.sender """
        return self.sender(email)

    def output(self, output_file):
        self._output = output_file
        return self

    def gpg(self, gnugp_home=True):
        """
        :param gnugp_home: String for GnuPG home or True.
        """
        self._gpg = gnugp_home
        return self

    def smime(self):
        self._gpg = False
        return self

    def subject(self, subject):
        self._subject = subject
        return self

    def list_unsubscribe(self, uri=None, one_click=False, *, web=None, email=None):
        """ The header will not be encrypted with GPG nor S/MIME.
        :param uri: Web or e-mail address.
            We try to determine whether this is e-mail and prepend brackets and 'https:'/'mailto:' if needed
            Ex: "me@example.com?subject=unsubscribe", "example.com/unsubscribe", "<https://example.com/unsubscribe>"
        :param one_click: If True, rfc8058 List-Unsubscribe-Post header is added.
            This says user can unsubscribe with a single click that is realized by a POST request
            in order to prevent e-mail scanner to access the unsubscribe page by mistake. A 'https' url must be present.
        :param web: URL. Ex: "example.com/unsubscribe", "http://example.com/unsubscribe"
        :param email: E-mail address. Ex: "me@example.com", "mailto:me@example.com"
        :return: self
        """

        elements = []
        if "List-Unsubscribe" in self._headers:
            elements.extend(self._headers["List-Unsubscribe"].split(","))

        if one_click:
            self.header("List-Unsubscribe-Post", "List-Unsubscribe=One-Click")
            if uri and not web:  # we are sure this is web because one-click header does not go with an e-mail
                web = uri
                uri = None

        if uri.startswith("<"):
            elements.append(uri)
        elif uri.startswith(("http:", "https:", "mailto:", "//")):
            elements.append(f"<{uri}>")
        elif "@" in uri:
            elements.append(f"<mailto:{uri}>")
        else:
            elements.append(f"<https://{uri}>")

        if web:
            if uri.startswith(("http:", "https:", "//")):
                elements.append(f"<{web}>")
            else:
                elements.append(f"<https://{web}>")

        if email:
            if uri.startswith("mailto:"):
                elements.append(f"<{email}>")
            else:
                elements.append(f"<mailto:{email}>")

        self.header("List-Unsubscribe", ", ".join(elements))
        return self

    auto_submitted: AutoSubmittedHeader

    def header(self, key, val):
        """ Add a generic header.
        The header will not be encrypted with GPG nor S/MIME.
        :param key: Header name
        :param val: Header value
        :return:
        """
        self._headers[key] = val
        return self

    def smtp(self, host="localhost", port=25, user=None, password=None, security=None):
        """
        Obtain SMTP server connection.
        Note that you may safely call this in a loop,
            envelope will remember the settings and connect only once (without reconnecting every iteration).
        :param host: hostname, smtplib.SMTP or INI file path.
        :param port:
        :param user:
        :param password:
        :param security: Ex: tlsstart
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
            self._smtp = SMTP(**host)
        elif type(host) is list:  # ex: ["localhost", 1234]
            self._smtp = SMTP(*host)
        elif isinstance(host, smtplib.SMTP):
            self._smtp = SMTP(host)
        else:
            self._smtp = SMTP(host, port, user, password, security)
        return self

    def to(self, email_or_list):
        self._to += assure_list(email_or_list)
        return self

    def attach(self, attachment_or_list=None, mimetype=None, filename=None, *, path=None):
        # "path"/Path, [mimetype/filename], [mimetype/filename]
        if type(attachment_or_list) is list:
            if path or mimetype or filename:
                raise ValueError("Cannot specify both path, mimetype or filename and put list in attachment_or_list.")
        else:
            if path:
                attachment_or_list = Path(path)
            attachment_or_list = attachment_or_list, mimetype, filename
        self._attachments += assure_list(attachment_or_list)
        return self

    def signature(self, key=True, passphrase=None, attach_key=False, cert=None, *, key_path=None):
        """
        Turn signing on.
        :param key: Signing key
            * GPG: Blank for user default key or key ID/fingerprint.
            * S/MIME: Any fetchable contents with key to be signed with. May contain signing certificate as well.
        :param passphrase: Passphrase to the key if needed.
        :param attach_key: GPG: Append public key to the attachments when sending.
        :param cert: S/MIME: Any fetchable contents with certificate to be signed with.
        :param key_path: Path to a file with the `key`.
        """
        if key_path:
            key = Path(key_path)
        if key is True and self._sign not in [None, False]:
            # usecase envelope().signature(key=fingerprint).send(sign=True) should still have fingerprint in self._sign
            # (and not just "True")
            pass
        elif key is not None:
            # GPG: string, S/MIME: fetchable bytes
            # Do not call assure_fetched(bytes) because in GPG we need key fingerprint string.
            self._sign = key
        if passphrase is not None:
            self._passphrase = passphrase
        if attach_key is not None:
            self._attach_key = attach_key
        if cert is not None:
            if self._gpg is None:  # since cert is only for S/MIME, set S/MIME signing
                self.smime()
                self._gpg = False
            self._cert = assure_fetched(cert, bytes)
        return self

    def sign(self, key=True, passphrase=None, attach_key=False, cert=None, *, key_path=None):
        """
        Sign now.
        :param key: Signing key
            * GPG: Blank for user default key or key ID/fingerprint.
            * S/MIME: Any fetchable contents with key to be signed with. May contain signing certificate as well.
        :param passphrase: Passphrase to the key if needed.
        :param attach_key: GPG: Append public key to the attachments when sending.
        :param cert: S/MIME: Any fetchable contents with certificate to be signed with.
        :param key_path: Path to a file with the `key`.
        """
        self._processed = True
        self.signature(key=key, passphrase=passphrase, attach_key=attach_key, cert=cert, key_path=key_path)
        return self._start(sign=True)

    def encryption(self, key=True, *, key_path=None):
        """
        Turn encrypting on.
        :param key: Any fetchable contents with recipient GPG public key or S/MIME certificate to be encrypted with.
        :param key_path: Path to a file with the `key`.
        """
        if key_path:
            key = Path(key_path)
        if key is True and self._encrypt not in [None, False]:
            # usecase envelope().encrypt(key="keystring").send(encrypt=True) should still have key in self._encrypt
            # (and not just "True")
            pass
        elif key is not None:
            self._encrypt = assure_fetched(key, bytes)
        return self

    def encrypt(self, key=True, sign=None, *, key_path=None):
        """
        Encrypt now.
        :param key: True (for default GPG key) or any fetchable contents with recipient GPG public key or S/MIME certificate
                    to be encrypted with.
        :param sign: Turn signing on.
            * GPG: True or default signing key ID/fingerprint.
            * S/MIME: Any fetchable contents having the key + signing certificate combined in a single file.
              (If not in a single file, use .signature() method.)
        :param key_path: Path to a file with the `key`.
        """
        self._processed = True
        self.encryption(key=key, key_path=key_path)
        return self._start(encrypt=True, sign=sign)

    def send(self, send=True, sign=None, encrypt=None):
        """
        Send e-mail contents. To check e-mail was successfully sent, cast the returned object to bool.
        :param send: True to send now, False to print debug information.
        :param sign: Turn signing on.
            * GPG: True or default signing key ID/fingerprint.
            * S/MIME: Any fetchable contents having the key + signing certificate combined in a single file.
              (If not in a single file, use .signature() method.)
        :param encrypt: Any fetchable contents with recipient GPG public key or S/MIME certificate to be encrypted with.
        :return:
        """
        if self._processed:
            raise RuntimeError("Cannot call .send() after .sign()/.encrypt()."
                               " You probably wanted to use .signature()/.encryption() instead.")
        return self._start(sign=sign, encrypt=encrypt, send=send)

    def _start(self, sign=None, encrypt=None, send=None):
        """ Start processing. Either sign, encrypt or send the message and possibly set bool status of the object to True. """
        if sign is not None:
            self.signature(sign)
        if encrypt is not None:
            self.encryption(encrypt)

        # check if there is something to do
        sign = self._sign
        encrypt = self._encrypt
        if sign is None and encrypt is None and send is None:
            logger.warning("There is nothing to do – no signing, no encrypting, no sending.")
            return

        # assure streams are fetched and files are read from their paths
        data = self._message
        # we need a message
        if data is None:
            logger.error("Missing message")
            return False

        # determine if we are using gpg or smime
        gpg_on = None
        if encrypt or sign:
            if self._gpg is not None:
                gpg_on = bool(self._gpg)
            elif encrypt in Envelope._encrypts_cache:
                gpg_on = Envelope._encrypts_cache
            elif not gnupg and not smime:
                raise ImportError("Cannot import neither gnupg, neither smime.")
            elif not gnupg or not smime:
                gpg_on = bool(gnupg)
            else:
                try:
                    smime.encrypt("test", encrypt)  # XX will this work when smime signing implemented?
                except (ValueError, TypeError):
                    gpg_on = True
                else:
                    gpg_on = False
                finally:
                    Envelope._encrypts_cache[encrypt] = gpg_on

            if gpg_on:
                self._gnupg = gnupg.GPG(gnupghome=self._get_gnupg_home(), options=["--trust-model=always"],
                                        # XX trust model might be optional
                                        verbose=False) if sign or encrypt else None

        # if we plan to send later, convert text message to the email message object
        email = None
        if send is not None:
            email = self._prepare_email(data, encrypt and gpg_on, sign and gpg_on)
            if not email:
                return False
            data = email.as_bytes()

        # with GPG, encrypt or sign either text message or email message object
        micalg = None
        if encrypt or sign:
            if gpg_on:
                if encrypt:
                    data = self._encrypt_gpg_now(data, sign, encrypt)
                elif sign:
                    data, micalg = self._sign_gpg_now(data, sign, send)
            else:
                d = self._encrypt_smime_now(data, sign, encrypt)
                email = BytesParser().parsebytes(d.strip())  # smime always produces a Message object, not raw data
            if (gpg_on and not data) or (not gpg_on and not email):
                logger.error("Signing/encrypting failed.")
                return

        # sending email message object
        if send is not None:
            if gpg_on:
                if encrypt:
                    email = self._compose_gpg_encrypted(data)
                elif sign:  # gpg
                    email = self._compose_gpg_signed(email, data, micalg)
            elif encrypt or sign:  # smime
                # smime does not need additional EmailMessage to be included in, just restore Subject that has been
                # consumed in _encrypt_smime_now. It's interesting that I.E. "Reply-To" is not consumed there.
                email["Subject"] = self._subject
            email = self._send_now(email, encrypt, gpg_on, send)
            if not email:
                return

        # output to file or display
        if email or data:
            self._result.append(email.as_string() if email else assure_fetched(data, str))
            if self._output:
                with open(self._output, "wb") as f:
                    f.write(email.as_bytes() if email else data)
            self._status = True
        return self

    def _get_gnupg_home(self, readable=False):
        return self._gpg if type(self._gpg) is str else ("default" if readable else None)

    def _send_now(self, email, encrypt, encrypted_subject, send):
        try:
            if not self._sender and send is True:
                logger.error("You have to specify sender e-mail.")
                return False
            email["From"] = self._sender
            if self._to:
                email["To"] = ",".join(self._to)
            if self._cc:
                email["Cc"] = ",".join(self._cc)
            if self._reply_to:
                email["Reply-To"] = self._reply_to
        except IndexError as e:
            s = set(self._to + self._cc + self._bcc)
            if self._reply_to:
                s.add(self._reply_to)
            if self._sender:
                s.add(self._sender)
            logger.error(f"An e-mail address seem to be malformed.\nAll addresses: {s}\n{e}")
            return
        email["Date"] = formatdate(localtime=True)
        email["Message-ID"] = make_msgid()
        for k, v in self._headers.items():
            email[k] = v

        if send:
            failures = self._smtp.send_message(email, to_addrs=list(set(self._to + self._cc + self._bcc)))
            if failures:
                logger.warning(f"Unable to send to all recipients: {repr(failures)}.")
            elif failures is False:
                return False
        else:
            self._result.append("{}\nHave not been sent from {} to {}" \
                                .format("*" * 100, (self._sender or ""), ", ".join(set(self._to + self._cc + self._bcc))))
            if encrypt:
                if encrypted_subject:
                    self._result.append(f"Encrypted subject: {self._subject}")
                self._result.append(f"Encrypted message: {self._message}")
            self._result.append("")

        return email

    def _sign_gpg_now(self, message, sign, send):
        status = self._gnupg.sign(
            message,
            extra_args=["--textmode"],
            # textmode: Enigmail had troubles to validate even though signature worked in CLI https://superuser.com/questions/933333
            keyid=sign if sign and sign is not True else None,
            passphrase=self._passphrase if self._passphrase else None,
            detach=True if send is not None else None,
        )
        try:  # micalg according to rfc4880
            micalg = "pgp-" + {1: "MD5",
                               2: "SHA1",
                               3: "RIPEMD160",
                               8: "SHA256",
                               9: "SHA384",
                               10: "SHA512",
                               11: "SHA224"}[int(status.hash_algo)].lower()
        except KeyError:  # alright, just unknown algorithm
            micalg = None
        except TypeError:  # signature failed
            logger.error(status.stderr)
            return False, None
        return status.data, micalg

    def _encrypt_gpg_now(self, message, sign, encrypt):
        exc = []
        if not self._to and not self._cc and not self._bcc:
            exc.append("No recipient e-mail specified")
        if self._sender is None:
            exc.append("No sender e-mail specified. If not planning to decipher later, put sender=False or --no-sender flag.")
        if exc:
            raise RuntimeError("Encrypt key present. " + ", ".join(exc))
        if type(encrypt) is str:  # when True all keys are supposed to be in the keyring
            # XX it should be possible to pass a key-id too, not only the key-data
            # XXX multiple recipients allowed
            self._gnupg.import_keys(encrypt)
        deciphering = set(self._to + self._cc + self._bcc + ([self._sender] if self._sender else []))
        status = self._gnupg.encrypt(
            data=message,
            recipients=deciphering,
            sign=sign if sign else None,
            passphrase=self._passphrase if self._passphrase else None
        )
        if status.ok:
            return status.data
        else:
            logger.warning(status.stderr)
            if "No secret key" in status.stderr:
                logger.warning(f"Secret key not found in {self._get_gnupg_home()} home folder. Create one.")
            if "Bad passphrase" in status.stderr:
                logger.warning(f"Bad passphrase for key.")
            if "Operation cancelled" in status.stderr:
                logger.info(f"You cancelled the key prompt.")
            if "Syntax error in URI" in status.stderr:
                logger.info(f"Unable to download missing key.")
            if any(s in status.stderr for s in ["No name", "No data", "General error", "Syntax error in URI"]):
                keys = [uid["uids"] for uid in self._gnupg.list_keys()]
                found = False
                for identity in deciphering:
                    if not [k for k in keys if [x for x in k if identity in x]]:
                        found = True
                        logger.warning(f"Key for {identity} seems missing.")
                if found:
                    s = self._get_gnupg_home()
                    s = f"GNUPGHOME={s} " if s else ""
                    logger.warning(f"See {s} gpg --list-keys")
            return False

    def _encrypt_smime_now(self, email, sign, encrypt):
        with warnings.catch_warnings():
            # m2crypto.py:13: DeprecationWarning: the imp module is deprecated in favour of importlib;
            # see the module's documentation for alternative uses import imp
            warnings.simplefilter("ignore", category=DeprecationWarning)
            from M2Crypto import BIO, Rand, SMIME, X509, EVP  # we save up to 30 - 120 ms to load it here
        output_buffer = BIO.MemoryBuffer()
        signed_buffer = BIO.MemoryBuffer()
        content_buffer = BIO.MemoryBuffer(email)

        # Seed the PRNG.
        temp = str(Path(tempfile.gettempdir(), 'envelope-randpool.dat'))
        Rand.load_file(temp, -1)

        # Instantiate an SMIME object.
        smime = SMIME.SMIME()

        if sign:
            # Since s.load_key shall not accept file contents, we have to set the variables manually
            sign = assure_fetched(sign, bytes)
            # XX remove getpass conversion to bytes callback when https://gitlab.com/m2crypto/m2crypto/issues/260 is resolved
            cb = (lambda x: bytes(self._passphrase, 'ascii')) if self._passphrase else (lambda x: bytes(getpass(), 'ascii'))
            smime.pkey = EVP.load_key_string(sign, callback=cb)
            if self._cert:
                cert = self._cert
            else:
                cert = sign
            smime.x509 = X509.load_cert_string(cert)
            if not encrypt:
                p7 = smime.sign(content_buffer, SMIME.PKCS7_DETACHED)
                content_buffer = BIO.MemoryBuffer(email)  # we have to recreate it because it was sucked out
                smime.write(output_buffer, p7, content_buffer)
            else:
                p7 = smime.sign(content_buffer)
                smime.write(signed_buffer, p7)
                content_buffer = signed_buffer
        if encrypt:
            sk = X509.X509_Stack()
            sk.push(X509.load_cert_string(encrypt))  # XXX multiple recipients - may be loaded from a directory by from, to, sender?
            smime.set_x509_stack(sk)
            smime.set_cipher(SMIME.Cipher('des_ede3_cbc'))  # Set cipher: 3-key triple-DES in CBC mode.

            # Encrypt the buffer.
            p7 = smime.encrypt(content_buffer)
            smime.write(output_buffer, p7)

        Rand.save_file(temp)
        return output_buffer.read()

    def _compose_gpg_signed(self, email, text, micalg=None):
        msg_payload = email
        email = EmailMessage()
        email["Subject"] = self._subject
        email.set_type("multipart/signed")
        email.set_param("protocol", "application/pgp-signature")
        if micalg:
            email.set_param("micalg", micalg)
        email.attach(msg_payload)
        msg_signature = EmailMessage()
        msg_signature['Content-Type'] = 'application/pgp-signature; name="signature.asc"'
        msg_signature['Content-Description'] = 'OpenPGP digital signature'
        msg_signature['Content-Disposition'] = 'attachment; filename="signature.asc"'
        msg_signature.set_payload(text)
        email.attach(msg_signature)
        return email

    @staticmethod
    def _compose_gpg_encrypted(text):
        # encrypted message structure according to RFC3156
        email = EmailMessage()
        email["Subject"] = "Encrypted message"  # real subject should be revealed when decrypted
        email.set_type("multipart/encrypted")
        email.set_param("protocol", "application/pgp-encrypted")
        msg_version = EmailMessage()
        msg_version["Content-Type"] = "application/pgp-encrypted"
        msg_version.set_payload("Version: 1")
        msg_text = EmailMessage()
        msg_text["Content-Type"] = 'application/octet-stream; name="encrypted.asc"'
        msg_text["Content-Description"] = "OpenPGP encrypted message"
        msg_text["Content-Disposition"] = 'inline; filename="encrypted.asc"'
        msg_text.set_payload(text)  # text was replaced by a GPG stream
        email.attach(msg_version)
        email.attach(msg_text)
        return email

    def _prepare_email(self, text, encrypt_gpg, sign_gpg):
        # we'll send it later, transform the text to the e-mail first
        msg_text = EmailMessage()
        # XX make it possible to be "plain" here + to have "plain" as the automatically generated html for older browsers
        msg_text.set_content(text.decode("utf-8"), subtype="html")

        if self._attach_key:  # send your public key as an attachment (so that it can be imported before it propagates on the server)
            keyid = self._sign
            if keyid is True:
                for key in self._gnupg.list_keys(True):  # if no default key is given, pick the first secret as a default
                    keyid = key["keyid"]
                    break
            if type(keyid) is str:
                contents = self._gnupg.export_keys(keyid)
                self.attach(contents, "public-key.asc")

        failed = False
        for contents in self._attachments:
            # get contents, user defined name and user defined mimetype
            # "path"/Path, [mimetype/filename], [mimetype/filename]
            name = mimetype = None
            if type(contents) is tuple:
                for s in contents[1:]:
                    if not s:
                        continue
                    elif "/" in s:
                        mimetype = s
                    else:
                        name = s
                contents = contents[0]
            if not name and isinstance(contents, Path):
                name = contents.name
            try:
                data = assure_fetched(contents, bytes)
            except FileNotFoundError:
                logger.error(f"Could not fetch file {contents.absolute()}")
                failed = True
                continue
            if not mimetype:
                mimetype = getattr(magic.Magic(mime=True), "from_file" if isinstance(contents, Path) else "from_buffer")(
                    str(contents))
            msg_text.add_attachment(data,
                                    maintype=mimetype.split("/")[0],
                                    subtype=mimetype.split("/")[1],
                                    filename=name or "attachment.txt")
        if failed:
            return False
        if encrypt_gpg:  # GPG inner message definition
            # in order to encrypt subject field → encapsulate the message into multipart having rfc822-headers submessage
            email = EmailMessage()
            email.set_type("multipart/mixed")
            email.set_param("protected-headers", "v1")

            msg_headers = EmailMessage()
            msg_headers.set_param("protected-headers", "v1")
            msg_headers.set_content(f"Subject: {self._subject}")
            msg_headers.set_type("text/rfc822-headers")  # must be set after set_content, otherwise reset to text/plain

            email.attach(msg_headers)
            email.attach(msg_text)
        else:  # plain message, smime or gpg-signed message
            email = msg_text
            if not sign_gpg:
                # due to an EmailMessage error (at least at Python3.7)
                # I cannot put diacritics strings like "Test =?utf-8?b?xZnFocW+xZnEjQ==?=" in subject
                # in inner message when GPG signing
                email["Subject"] = self._subject
        return email

    def check(self) -> bool:
        """
        If sender specified, check if DMARC DNS records exist and prints out the information.
        :rtype: bool SMTP connection worked
        """
        if self._sender:
            try:
                email = getaddresses([self._sender])[0][1]
                domain = email.split("@")[1]
            except IndexError:
                logger.warning(f"Could not parse domain from the sender address '{self._sender}'")
            else:
                def dig(query_or_list, rr="TXT", search_start=None):
                    if type(query_or_list) is not list:
                        query_or_list = [query_or_list]
                    for query in query_or_list:
                        try:
                            text = subprocess.check_output(["dig", "-t", rr, query]).decode("utf-8")
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
        print("Trying to connect to the SMTP...")
        return bool(self._smtp.connect())  # check SMTP


def _cli():
    global _cli_invoked
    _cli_invoked = True

    class BlankTrue(argparse.Action):
        """ When left blank, this flag produces True. (Normal behaviour is to produce None which I use for not being set."""

        def __call__(self, _, namespace, values, option_string=None):
            if values in [None, []]:  # blank argument with nargs="?" produces None, with ="*" produces []
                values = True
            setattr(namespace, self.dest, values)

    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--message', help='Plain text message.', metavar="TEXT")
    parser.add_argument('--input', help='Path to message file. (Alternative to `message` parameter.)', metavar="FILE")
    parser.add_argument('--output',
                        help='Path to file to be written to (else the contents is returned if ciphering or True if sending).',
                        metavar="FILE")
    parser.add_argument('--gpg', help='Home path to GNUPG rings else default ~/.gnupg is used.'
                                      'Leave blank for prefer GPG over S/MIME.', nargs="?", action=BlankTrue, metavar="PATH")
    parser.add_argument('--smime', action="store_true", help='Leave blank for prefer S/MIME over GPG.')
    parser.add_argument('--check', action="store_true", help='Check SMTP server connection')

    parser.add_argument('--sign', help='Sign the message.'
                                       ' GPG: Blank for user default key or key ID/fingerprint.'
                                       ' S/MIME: Key data.', nargs="?",
                        action=BlankTrue, metavar="FINGERPRINT|CONTENTS")
    parser.add_argument('--cert', help='S/MIME: Certificate contents if not included in the key.',
                        action=BlankTrue, metavar="CONTENTS")
    parser.add_argument('--passphrase', help='If signing key needs passphrase.')
    parser.add_argument('--sign-path', help='S/MIME: Filename with the sender\'s private key. (Alternative to `sign` parameter.)',
                        metavar="KEY-PATH")
    parser.add_argument('--cert-path', help='S/MIME: Filename with the sender\'s S/MIME private cert'
                                            ' if cert not included in the key. (Alternative to `cert` parameter.)',
                        metavar="CERT-PATH")

    parser.add_argument('--encrypt', help='Recipients public key string or 1 or true if the key should be in the ring from before.',
                        nargs="?", action=BlankTrue, metavar="GPG-KEY/SMIME-CERTIFICATE-CONTENTS")
    parser.add_argument('--encrypt-path', help='Filename with the recipient\'s public key. (Alternative to `encrypt` parameter.)',
                        metavar="PATH")
    parser.add_argument('-t', '--to', help="E-mail – needed to choose their key if encrypting", nargs="+", metavar="E-MAIL")
    parser.add_argument('--cc', help="E-mail or list", nargs="+", metavar="E-MAIL")
    parser.add_argument('--bcc', help="E-mail or list", nargs="+", metavar="E-MAIL")
    parser.add_argument('--reply-to', help="Header that states e-mail to be replied to. The field is not encrypted.",
                        metavar="E-MAIL")
    parser.add_argument('-f', '--from', help="Alias of --sender", metavar="E-MAIL")
    parser.add_argument('--sender', help="E-mail – needed to choose our key if encrypting", metavar="E-MAIL")
    parser.add_argument('--no-sender', action="store_true",
                        help="We explicitly say we do not want to decipher later if encrypting.")
    parser.add_argument('-a', '--attachment',
                        help="Path to the attachment, followed by optional file name to be used and/or mimetype."
                             " This parameter may be used multiple times.",
                        nargs="+", action="append")
    parser.add_argument('--attach-key', help="Appending public key to the attachments when sending.", action="store_true")

    parser.add_argument('--send', help="Send e-mail. Blank to send now.", nargs="?", action=BlankTrue)
    parser.add_argument('-s', '--subject', help="E-mail subject")
    parser.add_argument('--smtp', help="SMTP server. List `host, [port, [username, password, [security]]]` or dict.\n"
                                       "Ex: '--smtp {\"host\": \"localhost\", \"port\": 25}'."
                                       " Security may be explicitly set to 'starttls', 'tls' or automatically determined by port.",
                        nargs="*", action=BlankTrue, metavar=("HOST", "PORT"))
    parser.add_argument('--header',
                        help="Any e-mail header in the form `name value`. Flag may be used multiple times.",
                        nargs=2, action="append", metavar=("NAME", "VALUE"))
    parser.add_argument('-q', '--quiet', help="Quiet output", action="store_true")

    # envelope = Envelope()
    args = vars(parser.parse_args())

    # cli arguments
    quiet = args.pop("quiet")

    # in command line, we may specify input message by path (in module we would rather call message=Path("path"))
    if args["input"]:
        if args["message"]:
            raise RuntimeError("Cannot define both input and message.")
        args["message"] = Path(args["input"])
    del args["input"]

    # we explicitly say we do not want to decipher later if encrypting
    if args["no_sender"]:
        args["sender"] = False
    del args["no_sender"]

    # user is saying that encryption key has been already imported
    enc = args["encrypt"]
    if enc and enc is not True:
        if enc.lower() in ["1", "true", "yes"]:
            args["encrypt"] = True
        elif enc.lower() in ["0", "false", "no"]:
            args["encrypt"] = False

    # user specified encrypt key in a path. And did not disabled encryption
    if args["encrypt_path"] and args["encrypt"] is not False:
        if args["encrypt"] not in [True, None]:  # user has specified both path and the key
            raise RuntimeError("Cannot define both encrypt key data and encrypt key path.")
        args["encrypt"] = Path(args["encrypt_path"])
    del args["encrypt_path"]

    # user specified sign key in a path. And did not disabled signing
    if args["sign_path"] and args["sign"] is not False:
        if args["sign"] not in [True, None]:  # user has specified both path and the key
            raise RuntimeError("Cannot define both sign key data and sign key path.")
        args["sign"] = Path(args["sign_path"])
    del args["sign_path"]

    if args["cert_path"]:
        if args["cert"] is not None:
            raise RuntimeError("Cannot define both cert and cert-path.")
        args["cert"] = Path(args["cert_path"])
    del args["cert_path"]

    # smtp can be a dict
    if args["smtp"] and args["smtp"][0].startswith("{"):
        args["smtp"] = decode(" ".join(args["smtp"]))

    # send = False turns on debugging
    if args["send"] and type(args["send"]) is not bool:
        if args["send"].lower() in ["0", "false", "no"]:
            args["send"] = False
        elif args["send"].lower() in ["1", "true", "yes"]:
            args["send"] = True

    # convert to the module-style attachments `/tmp/file.txt text/plain` → (Path("/tmp/file.txt"), "text/plain")
    args["attachments"] = []
    if args["attachment"]:
        for attachment in args["attachment"]:
            attachment[0] = Path(attachment[0])  # path-only (no direct content) allowed in CLI
            # we cast to tuple because so that single attachment is not mistanek for list of attachments
            args["attachments"].append(tuple(attachment))
    del args["attachment"]

    args["headers"] = args["header"]
    del args["header"]

    if args["from"]:
        args["sender"] = args["from"]
    del args["from"]

    if args["check"]:
        del args["sign"]
        del args["encrypt"]
        del args["send"]
        del args["check"]
        o = Envelope(**args)
        if o.check():
            print("Check succeeded.")
            sys.exit(0)
        else:
            print("Check failed.")
            sys.exit(1)
    del args["check"]

    if not any([args["sign"], args["encrypt"], args["send"]]):
        # if there is anything to do, pretend the input parameters are a bone of a message
        print(str(Envelope(**args)))
        sys.exit(0)

    res = Envelope(**args)
    if res:
        if not quiet:
            print(res)
    else:
        sys.exit(1)


if __name__ == "__main__":
    _cli()
else:
    Envelope._cli = _cli
    Envelope.default = Envelope()
