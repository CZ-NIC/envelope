#!/usr/bin/env python3

import argparse
import io
import logging
import mimetypes
import smtplib
import sys
from email.message import Message, EmailMessage
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.policy import SMTP
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


class Gpggo:

    def __init__(self):
        self.message = None
        self.output = None
        self.gnupg = None
        self.sign = None
        self.passphrase = None
        self.encrypt = None
        self.recipients = None
        self.sender = None
        self.cc = None
        self.bcc = None
        self.subject = None
        self.smtp = None
        self.reply_to = None
        self.attachments = None

    def __call__(self, message=None, output=None, gnupg=None,
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
        :param attachments: Attachment or their list. Attachment is defined by file path or stream (ex: from open()), optionaly in tuple with the file name in the e-mail.
        """
        # check if there is something to do
        if sign is not True and encrypt is None and send is None:
            logger.warning("There is nothing to do – no signing, no ecrypting, no sending.")
            return False

        # load default values
        message = message or self.message
        output = output or self.output
        gnupg = gnupg or self.gnupg
        sign = sign or self.sign
        passphrase = passphrase or self.passphrase
        encrypt = encrypt or self.encrypt
        recipients = recipients or self.recipients
        sender = sender if sender is not None else self.sender  # we may set sender=False
        subject = subject or self.subject
        bcc = bcc or self.bcc
        cc = cc or self.cc
        reply_to = reply_to or self.reply_to
        attachments = attachments or self.attachments

        # we need a message
        if message is None:
            raise RuntimeError("Missing message")

        # assure streams are fetched and files are read from their paths
        message = assure_fetched(message, bytes)
        encrypt = assure_fetched(encrypt, str)
        text = message
        recipients = assure_list(recipients)
        cc = assure_list(cc)
        bcc = assure_list(bcc)
        attachments = assure_list(attachments)

        # encrypt or sign
        gpg = gnupglib.GPG(gnupghome=gnupg, options=["--trust-model=always"],  # XX trust model should be optional only
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
                passphrase=passphrase if passphrase else None
            )
            if status.ok:
                text = status.data
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
                        s = f"GNUPGHOME={gnupg} " if gnupg else ""
                        logger.warning(f"See {s}gpg --list-keys")
                return False
            # print(status.ok)
            # print(status.status)
            # print(status.stderr)
        elif sign:
            status = gpg.sign(
                message,
                keyid=sign if sign and sign is not True else None,
                passphrase=passphrase if passphrase else None
            )
            text = status.data

        # sending file
        if send in [True, False]:

            base_msg = EmailMessage()
            base_msg.set_content(text.decode("utf-8"), subtype="html")

            for contents in attachments:
                # get contents, user defined name and user defined mimetype
                # "path"/Path[, mimetype/filename[, mimetype/filename]]
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
                    mimetype = getattr(magic.Magic(mime=True), "from_file" if isinstance(contents, Path) else "from_buffer")(str(contents))
                base_msg.add_attachment(assure_fetched(contents, bytes),
                                       maintype=mimetype.split("/")[0],
                                       subtype=mimetype.split("/")[1],
                                       filename=name or "attachment.txt")

            msg = base_msg

            msg["From"] = sender or ""
            msg["Subject"] = subject
            if recipients:
                msg["To"] = ",".join(recipients)
            if cc:
                msg["Cc"] = ",".join(cc)
            if bcc:  # XX Will it be possible to guess the number of recipients while encrypting? See the message size when having no bcc.
                msg["Bcc"] = ",".join(bcc)
            if reply_to:
                msg["Reply-To"] = reply_to
            msg["Date"] = formatdate(localtime=True)
            msg["Message-ID"] = make_msgid()

            if send:
                # XXX


                if not isinstance(smtp, smtplib.SMTP):
                    if type(smtp) is dict:  # ex: {"host": "localhost", "port": 1234}
                        smtp = self.set_smtp(**smtp)
                    elif type(smtp) is not str:  # ex: ["localhost", 1234]
                        smtp = self.set_smtp(*smtp)
                    else:  # ex: "localhost" or None
                        smtp = self.set_smtp(smtp)

                try:
                    smtp.send_message(msg)
                except smtplib.SMTPRecipientsRefused:
                    logger.warning(f"SMTP refuse to send an e-mail from the address {sender}")
                else:
                    if not output:
                        return True
            else:
                # XX should I test here SMTP is working?
                print("*" * 100 + f"\n\nHave not been sent:\nIntended path: " + (sender or "")+ " → " + ",".join(set(recipients +cc+bcc)) + "\n\n" + msg.as_string())
                return True

        # output to file or display
        if text:
            if output:
                with open(output, "wb") as f:
                    f.write(text)
                    return True
            else:
                return text

    def set_smtp(self, host="localhost", port=25, user=None, password=None, security=None):
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


sys.modules[__name__] = Gpggo()

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

    gpggo = Gpggo()
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

    res = gpggo(**args)
    if type(res) is not bool:
        print(res)
    if res is False:
        sys.exit(1)

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
