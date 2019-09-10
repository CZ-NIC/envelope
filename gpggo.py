#!/usr/bin/env python3
# Installation
# apt install gpg
# pip3 install python-gnupg
#


import argparse
import logging

import gnupg

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


def gpg(message=None, input=None, input_stream=None, output=None, gnupghome=None,
        sign=True, passphrase=None,
        encrypt_key=None, encrypt_key_path=None, recipient_email=None, sender_email=None):
    """
    :rtype: object If output not set, return output bytes, else True/False if output file was correctly written to.

    Input / Output
    :param message: Plain text message.
    :param input: Path to the message file. (Alternative to `message` parameter.)
    :param input_stream: Stream (ex: with open(...) as f) to be handled. (Alternative to `message` parameter.)
    :param output: Path to file to be written to (else the contents is returned).
    :param gnupghome: Path to GNUPG rings else default ~/.gnupg is used

    Signing
    :param sign: True or key id if the message is to be signed. (By default True.)
    :param passphrase: If signing key needs passphrase.

    Encrypting
    :param encrypt_key: Recipients public key string.
    :param encrypt_key_path: Filename with the recipients public key. (Alternative to `encrypt_key` parameter.)
    :param recipient_email: If encrypting, we need recipient's e-mail so that we choose the key they will be able to decipher it.
    :param sender_email: If encrypting we may add sender's e-mail so that we choose our key to be still able to decipher the message later.
    """
    # init gpg connector
    gpg = gnupg.GPG(gnupghome=gnupghome, options=["--trust-model=always"])
    result = None

    # import message
    if not message:
        if input:
            with open(input, "rb") as f:
                message = f.read()
        elif input_stream:
            message = input_stream.read()
        else:
            raise RuntimeError("Missing message")

    # import recipient's key
    if not encrypt_key and encrypt_key_path:
        with open(encrypt_key_path) as f:
            encrypt_key = f.read()

    # encrypt or sign
    if encrypt_key:
        if not recipient_email:
            raise RuntimeError("Encrypt key present but no recipient e-mail specified")
        gpg.import_keys(encrypt_key)
        status = gpg.encrypt(
            data=message,
            recipients=[e for e in (sender_email, recipient_email) if e is not None],
            sign=sign if sign else None,
            passphrase=passphrase if passphrase else None
        )
        if status.ok:
            result = status.data
        else:
            logger.warning(status.stderr)
            return False
        # print(status.ok)
        # print(status.status)
        # print(status.stderr)
        # print('~' * 50)
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


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--message', help='Plain text message.')
    parser.add_argument('--input',
                        help='Path to message file or stream (ex: with open(...) as f) to be handled. (Alternative to `message` parameter.)')
    parser.add_argument('--output', help='Path to file to be written to (else the contents is returned).')
    parser.add_argument('--gnupghome', help='Path to GNUPG rings else default ~/.gnupg is used')

    parser.add_argument('--sign', default=True, help='True or key id if the message is to be signed. (By default True.)')
    parser.add_argument('--passphrase', help='If signing key needs passphrase.')

    parser.add_argument('--encrypt_key', help='Recipients public key string.')
    parser.add_argument('--encrypt_key_path', help='Filename with the recipients public key.')
    parser.add_argument('--recipient_email',
                        help="If encrypting, we need recipient's e-mail so that we choose the key they will be able to decipher it.")
    parser.add_argument('--sender_email',
                        help="If encrypting we may add sender's e-mail so that we choose our key to be still able to decipher the message later.")

    print(gpg(**vars(parser.parse_args())))
