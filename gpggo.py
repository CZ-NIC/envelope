#!/usr/bin/env python3

import argparse
import io
import logging
import smtplib
import sys
from copy import copy
from email.message import EmailMessage
from email.utils import make_msgid, formatdate
from pathlib import Path

import gnupg as gnupglib
import magic
from jsonpickle import json

__doc__ = """

Quick layer over python-gnupg. You do not need to know everything about 
You insert either message in file or stream and receive signed and possibly encrypted output.

Usage:
  * launch as application, see ./gpg-quick.py --help
  * import as a module to your application, ex: `from gpg-quick import gpg` 

Example:

gpg(message="Hello world",
        output="/tmp/output_file",
        encrypt_key_path="/tmp/remote_key.asc",
        sender_email="me@email.com",
        recipient_email="remote_person@example.com")
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
    elif isinstance(message, io.IOBase):
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
        l = []
    elif type(l) is not list:
        l = [l]
    return l


class AutoSubmittedHeader:
    """  "auto-replied": direct response to another message by an automatic process """

    def __init__(self, parent: 'Gpggo'):
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


class Gpggo:
    default: 'Gpggo'

    _message = None
    _output = None
    _gnupg = None
    _sign = None
    _passphrase = None
    _encrypt = None
    _recipients = []
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

    def __bool__(self):
        # XXdocument
        return self._status

    def __str__(self):
        if self._result is None and (self._encrypt or self._sign):
            self._start()
        return assure_fetched(self._result, str)

    def __bytes__(self):
        return assure_fetched(self._result, bytes)

    def __eq__(self, other):
        if type(other) in [str, bytes]:
            return assure_fetched(self._result, bytes) == assure_fetched(other, bytes)

    def __init__(self, message=None, output=None, gnupg=None, headers=None,
                 sign=None, passphrase=None,
                 encrypt=None, recipients=None, sender=None,
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
        :param gnupg: Home folder of GNUPG rings else default ~/.gnupg is used

        Signing
        :param sign: True or key id if the message is to be signed.
        :param passphrase: If signing key needs passphrase.

        Encrypting
        :param encrypt: Recipients public key string or file path or stream (ex: from open()).
        :param recipients: E-mail or list. If encrypting used so that we choose the key they will be able to decipher with.
        :param sender: E-mail. If encrypting used so that we choose our key to be still able to decipher the message later with.
                        If False, we explicitly declare to give up on deciphering later.

        Sending
        :param subject: E-mail subject
        :param reply_to: Reply to header
        :param smtp: tuple or dict of these optional parameters: host, port, username, password, security ("tlsstart")
        :param send: True for sending the mail. False will just print the output.
        :param cc: E-mail or their list.
        :param bcc: E-mail or their list. XXIdentity may be exposed by design when encrypting.
        :param attachments: Attachment or their list. Attachment is defined by file path or stream (ex: from open()),
            optionally in tuple with the file name in the e-mail and/or mimetype.
        :param headers: List of headers which are tuples of name, value. Ex: [("X-Mailer", "my-cool-application"), ...]
        """
        self._status = False  # whether we successfully encrypted/signed/send
        self._result = ""  # text output for str() conversion
        self.auto_submitted = AutoSubmittedHeader(self)  # allows fluent interface to set header

        # load default values
        # self._message = self._output = self._gnupg = self._sign = self._passphrase = self._encrypt = \
        #     self._sender = self._subject = self._reply_to = self._smtp = self._send = None
        # self._recipients = []
        # self._attachments = []
        # self._cc = []
        # self._bcc = []

        # if a parameter is not set, use class defaults, else init with parameter
        for k, v in locals().items():
            if k in ["self", "send"]:
                continue
            elif v is None:
                if hasattr(self, "default"):
                    v = copy(getattr(self.default, "_" + k))  # ex `v = copy(self.default._message)`
            elif k == "passphrase":
                self.signature(passphrase=v)
            elif k == "recipients":
                self.recipient(v)
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

        # message = message or copy(self.message)
        # output = output or copy(self.output)
        # gnupg = gnupg or copy(self.gnupg)
        # sign = sign or copy(self.sign)
        # passphrase = passphrase or copy(self.passphrase)
        # encrypt = encrypt or copy(self.encrypt)
        # recipients = recipients or copy(self.recipients)
        # sender = sender if sender is not None else self.sender  # we may set sender=False
        # subject = subject or copy(self.subject)
        # bcc = bcc or copy(self.bcc)
        # cc = cc or copy(self.cc)
        # reply_to = reply_to or copy(self.reply_to)
        # attachments = attachments or copy(self.attachments)

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

    def output(self, output_file):
        self._output = output_file
        return self

    def gnupg(self, gpnugp_home):
        self._gnupg = gpnugp_home
        return self

    def subject(self, subject):
        self._subject = subject
        return self

    def list_unsubscribe(self, url_or_email=None, one_click=False, *, url=None, email=None):
        """ The header will not be encrypted with GPG nor S/MIME.
        :param url_or_email: URL or e-mail address.
            We try to determine whether this is e-mail and prepend brackets and 'https:'/'mailto:' if needed
            Ex: "me@example.com?subject=unsubscribe", "example.com/unsubscribe", "<https://example.com/unsubscribe>"
        :param one_click: If True, rfc8058 List-Unsubscribe-Post header is added.
            This says user can unsubscribe with a single click that is realized by a POST request
            in order to prevent e-mail scanner to access the unsubscribe page by mistake. A 'https' url must be present.
        :param url: URL. Ex: "example.com/unsubscribe", "http://example.com/unsubscribe"
        :param email: E-mail address. Ex: "me@example.com", "mailto:me@example.com"
        :return: self
        """

        elements = []
        if "List-Unsubscribe" in self._headers:
            elements.extend(self._headers["List-Unsubscribe"].split(","))

        if url_or_email.startswith("<"):
            elements.append(url_or_email)
        elif url_or_email.startswith(("http:", "https:", "mailto:", "//")):
            elements.append(f"<{url_or_email}>")
        elif "@" in url_or_email:
            elements.append(f"<mailto:{url_or_email}>")
        else:
            elements.append(f"<https://{url_or_email}>")

        if url:
            if url_or_email.startswith(("http:", "https:", "//")):
                elements.append(f"<{url}>")
            else:
                elements.append(f"<https://{url}>")

        if email:
            if url_or_email.startswith("mailto:"):
                elements.append(f"<{email}>")
            else:
                elements.append(f"<mailto:{email}>")

        if one_click:
            self.header("List-Unsubscribe-Post", "List-Unsubscribe=One-Click")

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
        d = locals()
        del d["self"]
        # if isinstance(d, smtplib.SMTP):
        self._smtp = d
        return self

    def recipient(self, email_or_list):
        self._recipients += assure_list(email_or_list)
        return self

    def attach(self, attachment_or_list=None, path=None, mimetype=None, filename=None):
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

    def signature(self, key_id=True, passphrase=None):
        if key_id is True and type(self._sign) is str:
            # usecase gpggo().signature(key=fingerprint).send(sign=True) should still have fingerprint in self._sign
            # (and not just "True")
            pass
        else:
            self._sign = key_id if not None else True
        if passphrase is not None:
            self._passphrase = passphrase
        return self

    def sign(self, key_id=None, passphrase=None):
        self.signature(key_id=None, passphrase=None)
        return self._start(sign=True)

    def encryption(self, key_id=None, key_path=None, key=None):
        if key_path:
            key = Path(key_path)
        val = key_id or key
        if val is True and type(self._encrypt) is str:
            # usecase gpggo().encrypt(key="keystring").send(encrypt=True) should still have key in self._encrypt
            # (and not just "True")
            pass
        else:
            self._encrypt = assure_fetched(val, str)
        return self

    def encrypt(self, sign=None, key_id=None, key_path=None, key=None):
        self.encryption(key_id=None, key_path=None, key=None)
        return self._start(encrypt=True, sign=sign)

    def send(self, send=True, *, sign=None, encrypt=None):
        if sign is not None:
            self.signature(sign)
        if encrypt is not None:
            self.encryption(encrypt)
        return self._start(send=True, sign=False, encrypt=False)

    def _start(self, sign=False, encrypt=False, send=None):  # XXX
        # check if there is something to do
        if self._sign is not None:
            sign = self._sign
        if self._encrypt is not None:
            encrypt = self._encrypt
        if sign is not True and encrypt is None and send is None:
            logger.warning("There is nothing to do – no signing, no encrypting, no sending.")
            return


        # assure streams are fetched and files are read from their paths
        text = message = self._message
        encrypt = self._encrypt
        recipients = self._recipients
        cc = self._cc
        bcc = self._bcc
        sender = self._sender

        # we need a message
        if message is None:
            raise RuntimeError("Missing message")

        msg = None
        if send is not None:
            # we'll send it later, transform the text to the e-mail first
            msg_text = EmailMessage()
            msg_text.set_content(text.decode("utf-8"), subtype="html")

            for contents in self._attachments:
                # get contents, user defined name and user defined mimetype
                # "path"/Path, [mimetype/filename], [mimetype/filename]
                name = mimetype = None
                if type(contents) is tuple:
                    for s in contents[1:]:
                        if "/" in s:
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

            if encrypt:
                # in order to encrypt subject field → encapsulate the message into multipart having rfc822-headers submessage
                msg = EmailMessage()
                msg.set_type("multipart/mixed")
                msg.set_param("protected-headers", "v1")

                msg_headers = EmailMessage()
                msg_headers.set_type("text/rfc822-headers")
                msg_headers.set_param("protected-headers", "v1")
                msg_headers["Subject"] = self._subject
                # XX reply to, list-unsubscribe here? – zobrazí se reply-to ve zprávě, když je tady?

                msg.attach(msg_headers)
                msg.attach(msg_text)
            else:
                msg = msg_text
                msg["Subject"] = self._subject

            message = msg.as_bytes()

        # encrypt or sign
        gpg = gnupglib.GPG(gnupghome=(self._gnupg), options=["--trust-model=always"],  # XX trust model should be optional only
                           verbose=False) if sign or encrypt else None
        if encrypt:
            exc = []
            if not recipients and not cc and not bcc:
                exc.append("No recipient e-mail specified")
            if sender is None:
                exc.append("No sender e-mail specified. If not planning to decipher later, put sender=False or --no-sender flag.")
            if exc:
                raise RuntimeError("Encrypt key present. " + ", ".join(exc))

            if type(encrypt) is str:  # when True all keys are supposed to be in the keyring
                # XX what if this is a key-id?
                gpg.import_keys(encrypt)
            deciphering = set(x for x in recipients + [sender] + cc + bcc if x is not None)
            status = gpg.encrypt(
                data=message,
                recipients=deciphering,
                sign=sign if sign else None,
                passphrase=self._passphrase if self._passphrase else None
            )
            if status.ok:
                text = status.data
                self._status = True
            else:
                logger.warning(status.stderr)
                if "No secret key" in status.stderr:
                    logger.warning(f"Secret key not found in gpg home folder. Create one.")
                if "Bad passphrase" in status.stderr:
                    logger.warning(f"Bad passphrase for key.")
                if "Operation cancelled" in status.stderr:
                    logger.info(f"You cancelled the key prompt.")
                if "Syntax error in URI" in status.stderr:
                    logger.info(f"Unable to download missing key.")
                if any(s in status.stderr for s in ["No name", "No data", "General error", "Syntax error in URI"]):
                    keys = [uid["uids"] for uid in gpg.list_keys()]
                    found = False
                    for identity in deciphering:
                        if not [k for k in keys if [x for x in k if identity in x]]:
                            found = True
                            logger.warning(f"Key for {identity} seems missing.")
                    if found:
                        s = f"GNUPGHOME={self._gnupg} " if self._gnupg else ""
                        logger.warning(f"See {s}gpg --list-keys")
                return
            # print(status.ok)
            # print(status.status)
            # print(status.stderr)
        elif sign:
            status = gpg.sign(
                message,
                extra_args=["--textmode"],
                # Enigmail had troubles to validate even though signature worked in CLI (https://superuser.com/questions/933333)
                keyid=sign if sign and sign is not True else None,
                passphrase=self._passphrase if self._passphrase else None,
                detach=True if send is not None else None
            )

            text = status.data
            # import ipdb; ipdb.set_trace()
            # with open("/tmp/ram/2/foo.txt", "wb") as f:
            #     f.write(message)
            # with open("/tmp/ram/2/foo.sig", "wb") as f:
            #     f.write(text)
            self._status = True

        # sending file
        if send is not None:
            self._status = False
            if encrypt:
                # encrypted message structure according to RFC3156
                msg = EmailMessage()
                msg["Subject"] = "Encrypted message"  # real subject should be revealed when decrypted
                msg.set_type("multipart/encrypted")
                msg.set_param("protocol", "application/pgp-encrypted")

                msg_version = EmailMessage()
                msg_version["Content-Type"] = "application/pgp-encrypted"
                msg_version.set_payload("Version: 1")

                msg_text = EmailMessage()
                msg_text["Content-Type"] = 'application/octet-stream; name="encrypted.asc"'
                msg_text["Content-Description"] = "OpenPGP encrypted message"
                msg_text["Content-Disposition"] = 'inline; filename="encrypted.asc"'
                msg_text.set_payload(text)  # text was replaced by a GPG stream

                msg.attach(msg_version)
                msg.attach(msg_text)

            elif sign:
                msg_payload = msg
                msg = EmailMessage()
                msg[
                    "Subject"] = self._subject  # msg_payload["Subject"], diacritics threw error only when in subject and signing XX porad hazi error
                msg.set_type("multipart/signed")
                msg.set_param("protocol", "application/pgp-signature")
                msg.attach(msg_payload)

                msg_signature = EmailMessage()
                msg_signature['Content-Type'] = 'application/pgp-signature; name="signature.asc"'
                msg_signature['Content-Description'] = 'OpenPGP digital signature'
                msg_signature['Content-Disposition'] = 'attachment; filename="signature.asc"'
                msg_signature.set_payload(text)
                msg.attach(msg_signature)

            msg["From"] = sender or ""
            if recipients:
                msg["To"] = ",".join(recipients)
            if cc:
                msg["Cc"] = ",".join(cc)
            # I don't see any advantage in listing Bcc here. MTA should take them off. (And they stay here while encrypting.)
            # if bcc:  # XX Will it be possible to guess the number of recipients while encrypting? See the message size when having no bcc.
            #    msg["Bcc"] = ",".join(bcc)
            if self._reply_to:  # XX shouldnt we add him to the decipherers too? even if he wont receive the message, he ll get replies
                msg["Reply-To"] = self._reply_to
            msg["Date"] = formatdate(localtime=True)
            msg["Message-ID"] = make_msgid()

            for k, v in self._headers.items():
                msg[k] = v

            if send:
                smtp = self._smtp


                if not isinstance(smtp, smtplib.SMTP):
                    key = repr(smtp)
                    if key not in Gpggo._smtps:
                        if type(smtp) is dict:  # ex: {"host": "localhost", "port": 1234}
                            smtp = self._smtp_connect(**smtp)
                        elif type(smtp) is not str:  # ex: ["localhost", 1234]
                            smtp = self._smtp_connect(*smtp)
                        else:  # ex: "localhost" or None
                            smtp = self._smtp_connect(smtp)
                        Gpggo._smtps[key] = smtp
                    else:
                        smtp = Gpggo._smtps[key]

                try:
                    smtp.send_message(msg,
                                      to_addrs=list(
                                          set(recipients + cc + bcc)))  # to_addrs cannot be taken from headers when encrypting
                except smtplib.SMTPRecipientsRefused:
                    logger.warning(f"SMTP refuses to send an e-mail from the address {sender}")
                # except Timeout: XX
                #    continue somehow
                # else:
                # if not self._output:
                #     self._status = True
                #     return
            else:
                # XX should I test here SMTP is working?
                # print("*" * 100 + f"\n\nHave not been sent:\nIntended path: " + (sender or "") + " → " + ",".join(
                #     set(recipients + cc + bcc))) # + "\n\n" + msg.as_string())
                # print("**********")
                # self._status = True
                self._result = "{}\nHave not been sent:\nIntended path: {}  → {}\n" \
                    .format("*" * 100, (sender or ""), ",".join(set(recipients + cc + bcc)))
            self._status = True
            # return

        # output to file or display
        if text:
            self._result += assure_fetched(text, str)
            # print("HEJ", self._result)
            if self._output:
                with open(self._output, "wb") as f:
                    f.write(text)
            self._status = True

    def _smtp_connect(self, host="localhost", port=25, user=None, password=None, security=None):
        smtp = smtplib.SMTP(host, port)
        if security == "starttls":
            smtp.starttls()
        if user:
            try:
                smtp.login(user, password)
            except smtplib.SMTPAuthenticationError as e:
                logger.error(f"SMTP authentication failed for user {user} at host {host}.")
                raise
        self.smtp = smtp
        return smtp


if __name__ == "__main__":
    class BlankTrue(argparse.Action):
        """ When left blank, this flag produces True. (Normal behaviour is to produce None which I use for not being set."""

        def __call__(self, _, namespace, values, option_string=None):
            if values in [None, []]:  # blank argument with nargs="?" produces None, with ="*" produces []
                values = True
            setattr(namespace, self.dest, values)


    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--message', help='Plain text message.')
    parser.add_argument('--input', help='Path to message file. (Alternative to `message` parameter.)')
    parser.add_argument('--output',
                        help='Path to file to be written to (else the contents is returned if ciphering or True if sending).')
    parser.add_argument('--gnupg', help='Home path to GNUPG rings else default ~/.gnupg is used')

    parser.add_argument('--sign', action="store_true", help='Sign the message. Blank for user default key or key-id.')
    parser.add_argument('--passphrase', help='If signing key needs passphrase.')

    parser.add_argument('--encrypt', help='Recipients public key string or 1 or true if the key should be in the ring from before.',
                        nargs="?", action=BlankTrue)
    parser.add_argument('--encrypt-file', help='Filename with the recipients public key. (Alternative to `encrypt` parameter.)')
    parser.add_argument('--recipients', help="E-mail – needed to choose their key if encrypting", nargs="+")
    parser.add_argument('--cc', help="E-mail or list", nargs="+")
    parser.add_argument('--bcc', help="E-mail or list", nargs="+")
    parser.add_argument('--reply-to', help="Header that states e-mail to be replied to")
    parser.add_argument('--sender', help="E-mail – needed to choose our key if encrypting")
    parser.add_argument('--no-sender', action="store_true",
                        help="We explicitly say we do not want to decipher later if encrypting.")
    parser.add_argument('--attachment',
                        help="Path to the attachment, followed by optional file name to be used and/or mimetype. This parameter may be used multiple times.",
                        nargs="+", action="append")

    parser.add_argument('--send', help="Send e-mail. Blank to send now.", nargs="?", action=BlankTrue)
    parser.add_argument('--subject', help="E-mail subject")
    parser.add_argument('--smtp', help="SMTP server. Blank or list (host, [port, [username, password]]) or dict XX examples",
                        nargs="*", action=BlankTrue)
    parser.add_argument('--header',
                        help="Any e-mail header in the form `name value`",
                        nargs="+", action="append")

    # gpggo = Gpggo()
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
        args["encrypt"] = Path(args["encrypt_path"])
    del args["encrypt_file"]

    # smtp can be a dict
    if args["smtp"] and len(args["smtp"]) == 1 and args["smtp"][0].startswith("{"):
        args["smtp"] = json.decode(args["smtp"][0])

    # send = False turns on debugging
    if args["send"] and type(args["send"]) is not bool and args["send"].lower() in ["0", "false", "no"]:
        args["send"] = False

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

    res = Gpggo(**args)  # Xgpggo
    if res:
        # print("HEJ2", res._result)
        print(res)
    else:
        sys.exit(1)
else:
    sys.modules[__name__] = Gpggo
    Gpggo.gpggo = Gpggo  # pycharm does not autocomplete # XX If the autocompletion doest not work in your IDE, try `gpggo.Gpggo`. Works in Jupyter, doesnt in PyCharm
    Gpggo.default = Gpggo()

    # if type(res) is not bool:
    #     print(res)
    # if res is False:
    #     sys.exit(1)

# XXX Address for representing e-mails?   Address(display_name='Aly Sivji', username='alysivji', domain='gmail.com'),
# XXX TO BE DIGGED OUT:

# if 0:
#     if self.parameters.gpg:
#         msg = MIMEMultipart(_subtype="signed", micalg="pgp-sha1", protocol="application/pgp-signature")
#     s = base_msg.as_string().replace('\n', '\r\n')
#     signature = self._sign(s)
#
#     if not signature:
#         print("Failed to sign the message for {}".format(email_to))
#     return False
#     signature_msg = Message()
#     signature_msg['Content-Type'] = 'application/pgp-signature; name="signature.asc"'
#     signature_msg['Content-Description'] = 'OpenPGP digital signature'
#     signature_msg.set_payload(signature)
#     msg.attach(base_msg)
#     msg.attach(signature_msg)
