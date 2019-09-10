# GPGGO

Quick layer over [python-gnupg](https://bitbucket.org/vinay.sajip/python-gnupg/src), its common usecases merged into single function. Want to sign a text and tired of forgetting how to do it right? You do not need to know everything about GPG. 
You insert a message and receive signed and/or encrypted output.

## Installation
If it's not already installed, you need `gpg` package. Then, you can directly fetch the GitHub code.
```bash 
sudo apt install gpg
pip3 install git+https://github.com/CZ-NIC/gpggo.git  # without root use may want to use --user
```

## Usage:
  * launch as application, see ./gpggo.py --help
  
```bash
./gpggo.py --message="Hello world" \
               --output="/tmp/output_file" \
               --encrypt_key_path="/tmp/remote_key.asc" \
               --sender_email="me@email.com" \
               --recipient_email="remote_person@example.com"
```
  * import as a function into your application 

```python3
from gpggo import gpg
gpg(message="Hello world",
        output="/tmp/output_file",
        encrypt_key_path="/tmp/remote_key.asc",
        sender_email="me@email.com",
        recipient_email="remote_person@example.com")
```

## Docs – list of commands
All parameters are optional.

### Input / Output
  * message: Plain text message.
  * input: Path to the message file. (Alternative to `message` parameter.)
  * input_stream: Stream (ex: with open(...) as f) to be handled. (Alternative to `message` parameter.)
  * output: Path to file to be written to (else the contents is returned).
  * gnupghome: Path to GNUPG rings else default ~/.gnupg is used
### Signing
  * sign: True or key id if the message is to be signed. (By default True.)
  * passphrase: If signing key needs passphrase.
### Encrypting
  * encrypt_key: Recipients public key string.
  * encrypt_key_path: Filename with the recipients public key. (Alternative to `encrypt_key` parameter.)
  * recipient_email: If encrypting, we need recipient's e-mail so that we choose the key they will be able to decipher it.
  * sender_email: If encrypting we may add sender's e-mail so that we choose our key to be still able to decipher the message later.
  
The same output should be accessible via `./gpggo.py --help`.