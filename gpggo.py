#!/usr/bin/env python3

import argparse
import io
import logging
import sys
from pathlib import Path

import gnupg as gnupglib

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
    """ Accepts object, returns its string or bytes. Object may be a string or a Path.
    If object is bool or none, it is returned as is.
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
        # self.smtp = None XX not implemented

    # XX attachment, subject, send (None,True,False for debug) parameter
    def __call__(self, message=None, output=None, gnupg=None,
                 sign=None, passphrase=None,
                 encrypt=None, recipients=None, sender=None,
                 smpt=None):
        """
        :rtype: object If output not set, return output bytes, else True/False if output file was correctly written to.

        Input / Output
        :param message: Plain text message or file path or stream (ex: from open()).
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
        """
        # load default values
        message = message or self.message
        output = output or self.output
        gnupg = gnupg or self.gnupg
        sign = sign or self.sign
        passphrase = passphrase or self.passphrase
        encrypt = encrypt or self.encrypt
        recipients = recipients or self.recipients
        sender = sender if sender is not None else self.sender  # we may set sender=False

        # init gpg connector
        gpg = gnupglib.GPG(gnupghome=gnupg, options=["--trust-model=always"],
                           verbose=False)  # XX trust model should be optional only

        # assure streams are fetched and files are read from their paths
        message = assure_fetched(message, bytes)
        encrypt = assure_fetched(encrypt, str)

        # we need a message
        if message is None:
            raise RuntimeError("Missing message")

        # encrypt or sign
        result = None
        if encrypt:
            exc = []
            if not recipients:
                exc.append("No recipient e-mail specified")
            if sender is None:
                exc.append("No sender e-mail specified. If not planning to decipher later, put sender=False or --no-sender flag.")
            if exc:
                raise RuntimeError("Encrypt key present. " + ", ".join(exc))

            if type(encrypt) is str:  # when True all keys are supposed to be in the keyring
                gpg.import_keys(encrypt)
            if type(recipients) is not list:
                recipients = [recipients]
            decipherers = recipients.copy()
            if sender:
                decipherers.append(sender)
            status = gpg.encrypt(
                data=message,
                recipients=decipherers,
                sign=sign if sign else None,
                passphrase=passphrase if passphrase else None
            )
            if status.ok:
                result = status.data
            else:
                logger.warning(status.stderr)
                if "No secret key" in status.stderr:
                    logger.warning(f"Secret key not found in gpg home folder. Create one.")
                if "Bad passphrase" in status.stderr:
                    logger.warning(f"Bad passphrase for key.")
                if "No name"  in status.stderr or "No data" in status.stderr:
                    keys = [uid["uids"] for uid in gpg.list_keys()]
                    for decipherer in decipherers:
                        if not [k for k in keys if decipherer in k]:
                            # for key in keys:
                            logger.warning(f"Key for {decipherer} seems missing.")
                return False
            # print(status.ok)
            # print(status.status)
            # print(status.stderr)
        elif not sign:
            raise RuntimeError("There is nothing to do – no signing, no ecrypting.")
        else:
            status = gpg.sign(
                message,
                keyid=sign if sign and sign is not True else None,
                passphrase=passphrase if passphrase else None
            )
            result = status.data

        # output to file or display
        if result:
            if output:
                with open(output, "wb") as f:
                    f.write(result)
                    return True
            else:
                return result


sys.modules[__name__] = Gpggo()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--message', help='Plain text message.')
    parser.add_argument('--input', help='Path to message file. (Alternative to `message` parameter.)')
    parser.add_argument('--output', help='Path to file to be written to (else the contents is returned).')
    parser.add_argument('--gnupg', help='Home path to GNUPG rings else default ~/.gnupg is used')

    parser.add_argument('--sign', action="store_true", help='Sign message. (Implicitly on if `sign-key` parameter used.)')
    parser.add_argument('--sign-key', help='Key id if the message is to be signed. (User default key used if not set.)')
    parser.add_argument('--passphrase', help='If signing key needs passphrase.')

    parser.add_argument('--encrypt', help='Recipients public key string or 1 or true if the key should be in the ring from before.')
    parser.add_argument('--encrypt-path', help='Filename with the recipients public key. (Alternative to `encrypt` parameter.)')
    parser.add_argument('--recipient', help="E-mail – needed to choose their key if encrypting")
    parser.add_argument('--sender', help="E-mail – needed to choose our key if encrypting")
    parser.add_argument('--no-sender', action="store_true",
                        help="We explicitly say we do not want to decipher later if encrypting.")

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

    # user can specify default key
    if args["sign_key"]:
        args["sign"] = args["sign-key"]
    del args["sign_key"]

    # user is saying that encryption key has been already imported
    enc = args["encrypt"]
    if enc:
        if enc.lower() in ["1", "true", "yes"]:
            args["encrypt"] = True
        elif enc.lower() in ["0", "false", "no"]:
            args["encrypt"] = False

    # user specified encrypt key in a path. And did not disabled encryption
    if args["encrypt_path"] and args["encrypt"] is not False:
        if args["encrypt"] not in [True, None]:  # user has specified both path and the key
            raise RuntimeError("Cannot define both encrypt and encrypt path.")
        args["encrypt"] = Path(args["encrypt_path"])
    del args["encrypt_path"]

    # we allow only one recipient in CLI currently
    args["recipients"] = args["recipient"]
    del args["recipient"]

    res = gpggo(**args)
    print(res)
    if res is False:
        sys.exit(1)
