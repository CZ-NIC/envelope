#!/usr/bin/env python3

import argparse
import io
import logging
import smtplib
import subprocess
import sys
from configparser import ConfigParser
from copy import copy
from email.message import EmailMessage
from email.utils import make_msgid, formatdate, getaddresses
from pathlib import Path
from socket import gaierror

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
            self.port = port
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
            smtp = smtplib.SMTP(self.host, self.port)
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

    _message = None
    _output = None
    _gpg: gnupg.GPG = None
    _sign = None
    _passphrase = None
    _attach_key = None
    _encrypt = None
    _to = []
    _sender = None
    _cc = []
    _bcc = []
    _subject = None
    _smtp = None
    _attachments = []
    _reply_to = None
    _headers = {}

    # cache of different smtp connections.
    # Usecase: user passes smtp server info in dict in a loop but we do want it connects just once
    _smtps = {}
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
        self._result = [s]  # slightly quicker next time if ever containing huge amount of lines
        return s

    def __init__(self, message=None, output=None, gpg=None, smime=None, headers=None,
                 sign=None, passphrase=None, attach_key=None,
                 encrypt=None, to=None, sender=None,
                 subject=None, cc=None, bcc=None, reply_to=None, attachments=None,
                 smtp=None, send=None):
        """
        :rtype: object If output not set, return output bytes, else True/False if output file was correctly written to.

        Any fetchable content means plain text, bytes or stream (ex: from open()).
        In *module interface*, you may use Path object to the file.
        In *CLI interface*, additional flags are provided.

        Input / Output
        :param message: Any fetchable content.
        :param output: Path to file to be written to (else the contents is returned).
        :param gpg: Home folder of GNUPG rings else default ~/.gnupg is used. Put True for prefer GPG over SMIME.

        Signing
        :param sign: True or key id if the message is to be signed.
        :param passphrase: If signing key needs passphrase.
        :param attach_key: If True, public key is appended as an attachment.

        Encrypting
        :param encrypt: Recipients public key string or file path or stream (ex: from open()).
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
                self.signature(attach_key=v)
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
        # CLI interface returns always a list or dict, ex: host=["localhost"] or host=["ini file"] or host={}
        # module one-liner interface fills host param, ex: host="localhost", host="ini file", host={"port": 123}, ["localhost", 123]
        # fluent interface fills all locals, ex: {"host": "ini file", "port": default 25}
        # Host can contain smtplib.SMTP or INI file path.

        # check for the presence of an INI file
        ini = None
        if type(host) is str:
            ini = host
        elif type(host) is list and len(host) > 0:
            ini = host[0]
        elif type(host) is dict and "host" in host:
            ini = host["host"]
        if ini and ini.endswith("ini") and Path(ini).exists():  # existing INI file
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
        else:
            d = locals()
            del d["self"]
            self._smtp = SMTP(**d)
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

    def signature(self, key=True, passphrase=None, attach_key=False):
        if key is True and type(self._sign) is str:
            # usecase envelope().signature(key=fingerprint).send(sign=True) should still have fingerprint in self._sign
            # (and not just "True")
            pass
        else:
            self._sign = key
        if passphrase is not None:
            self._passphrase = passphrase
        if attach_key is not None:
            self._attach_key = attach_key
        return self

    def sign(self, key=True, passphrase=None, attach_key=False):
        self._processed = True
        self.signature(key=key, passphrase=passphrase, attach_key=attach_key)
        return self._start(sign=True)

    def encryption(self, key=True, *, key_path=None):
        if key_path:
            key = Path(key_path)
        if key is True and type(self._encrypt) is str:
            # usecase envelope().encrypt(key="keystring").send(encrypt=True) should still have key in self._encrypt
            # (and not just "True")
            pass
        else:
            self._encrypt = assure_fetched(key, bytes)
        return self

    def encrypt(self, sign=None, key=True, *, key_path=None):
        self._processed = True
        self.encryption(key=key, key_path=key_path)
        return self._start(encrypt=True, sign=sign)

    def send(self, send=True, sign=None, encrypt=None):
        if self._processed:
            raise RuntimeError("Cannot call .send() after .sign()/.encrypt()."
                               " You probably wanted to use .signature()/.encryption() instead.")
        if sign is not None:
            self.signature(sign)
        if encrypt is not None:
            self.encryption(encrypt)
        return self._start(sign=sign, encrypt=encrypt, send=send)

    def _start(self, sign=False, encrypt=False, send=None):
        """ Start processing. Either sign, encrypt or send the message and possibly set bool status of the object to True. """
        # check if there is something to do
        if self._sign is not None:
            sign = self._sign
        if self._encrypt is not None:
            encrypt = self._encrypt
        if sign is not True and encrypt is None and send is None:
            logger.warning("There is nothing to do – no signing, no encrypting, no sending.")
            return

        # assure streams are fetched and files are read from their paths
        data = self._message
        encrypt = self._encrypt
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
            data = email.as_bytes()

        # with GPG, encrypt or sign either text message or email message object
        micalg = None
        if encrypt or sign:
            if gpg_on:
                if encrypt:
                    data = self._encrypt_now(data, sign, encrypt)
                elif sign:
                    data, micalg = self._sign_now(data, sign, send)
            else:
                if encrypt:
                    data = smime.encrypt(email, encrypt)
                elif sign:
                    raise NotImplementedError("S/MIME signing not yet implemented.")
            if not data:
                logger.error("Signing/encrypting failed.")
                return

        # sending email message object
        if send is not None:
            if encrypt and gpg_on:
                email = self._compose_gpg_encrypted(data)
            elif encrypt:
                email = data
            elif sign:  # gpg
                email = self._compose_gpg_signed(email, data, micalg)
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

    def _sign_now(self, message, sign, send):
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

    def _encrypt_now(self, message, sign, encrypt):
        exc = []
        if not self._to and not self._cc and not self._bcc:
            exc.append("No recipient e-mail specified")
        if self._sender is None:
            exc.append("No sender e-mail specified. If not planning to decipher later, put sender=False or --no-sender flag.")
        if exc:
            raise RuntimeError("Encrypt key present. " + ", ".join(exc))
        if type(encrypt) is str:  # when True all keys are supposed to be in the keyring
            # XX what if this is a key-id?
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
            if not mimetype:
                mimetype = getattr(magic.Magic(mime=True), "from_file" if isinstance(contents, Path) else "from_buffer")(
                    str(contents))
            msg_text.add_attachment(assure_fetched(contents, bytes),
                                    maintype=mimetype.split("/")[0],
                                    subtype=mimetype.split("/")[1],
                                    filename=name or "attachment.txt")
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
                                      'Leave blank for prefer GPG over S/MIME.', nargs="?", action=BlankTrue,metavar="PATH")
    parser.add_argument('--smime', action="store_true", help='Leave blank for prefer S/MIME over GPG.')
    parser.add_argument('--check', action="store_true", help='Check SMTP server connection')

    parser.add_argument('--sign', help='Sign the message. Blank for user default key or key ID/fingerprint.', nargs="?", action=BlankTrue, metavar="FINGERPRINT")
    parser.add_argument('--passphrase', help='If signing key needs passphrase.')

    parser.add_argument('--encrypt', help='Recipients public key string or 1 or true if the key should be in the ring from before.',
                        nargs="?", action=BlankTrue, metavar="KEY-CONTENTS")
    parser.add_argument('--encrypt-file', help='Filename with the recipients public key. (Alternative to `encrypt` parameter.)',metavar="PATH")
    parser.add_argument('--to', help="E-mail – needed to choose their key if encrypting", nargs="+", metavar="E-MAIL")
    parser.add_argument('--cc', help="E-mail or list", nargs="+", metavar="E-MAIL")
    parser.add_argument('--bcc', help="E-mail or list", nargs="+", metavar="E-MAIL")
    parser.add_argument('--reply-to', help="Header that states e-mail to be replied to. The field is not encrypted.", metavar="E-MAIL")
    parser.add_argument('--from', help="Alias of --sender", metavar="E-MAIL")
    parser.add_argument('--sender', help="E-mail – needed to choose our key if encrypting", metavar="E-MAIL")
    parser.add_argument('--no-sender', action="store_true",
                        help="We explicitly say we do not want to decipher later if encrypting.")
    parser.add_argument('-a', '--attachment',
                        help="Path to the attachment, followed by optional file name to be used and/or mimetype."
                             " This parameter may be used multiple times.",
                        nargs="+", action="append")
    parser.add_argument('--attach-key', help="Appending public key to the attachments when sending.", action="store_true")

    parser.add_argument('--send', help="Send e-mail. Blank to send now.", nargs="?", action=BlankTrue)
    parser.add_argument('--subject', help="E-mail subject")
    parser.add_argument('--smtp', help="SMTP server. List `host, [port, [username, password, [security]]]` or dict.\n"
                                       "Ex: '--smtp {\"host\": \"localhost\", \"port\": 25}'. Security may be 'starttls'.",
                        nargs="*", action=BlankTrue,metavar=("HOST", "PORT"))
    parser.add_argument('--header',
                        help="Any e-mail header in the form `name value`. Flag may be used multiple times.",
                        nargs=2, action="append", metavar=("NAME", "VALUE"))

    # envelope = Envelope()
    args = vars(parser.parse_args())

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
    if args["encrypt_file"] and args["encrypt"] is not False:
        if args["encrypt"] not in [True, None]:  # user has specified both path and the key
            raise RuntimeError("Cannot define both encrypt and encrypt path.")
        args["encrypt"] = Path(args["encrypt_file"])
    del args["encrypt_file"]

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
        print(res)
    else:
        sys.exit(1)


if __name__ == "__main__":
    _cli()
else:
    Envelope._cli = _cli
    Envelope.default = Envelope()
