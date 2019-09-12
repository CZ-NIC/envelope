# GPGGO

Quick layer over [python-gnupg](https://bitbucket.org/vinay.sajip/python-gnupg/src), its common usecases merged into single function. Want to sign a text and tired of forgetting how to do it right? You do not need to know everything about GPG, you do not have to bother with importing keys.
You insert a message and receive signed and/or encrypted output.

If the encryption fails, it tries to determine what recipient has the key missing.  

## Installation
If it's not already installed, you need `gpg` package. Then, you can directly fetch the GitHub code.
```bash 
sudo apt install gpg
pip3 install git+https://github.com/CZ-NIC/gpggo.git  # without root use may want to use --user
```

## Usage:
As an example, let's produce in two equal ways an `output_file` with the encrypted "Hello world" content.
### CLI
Launch as a CLI application in terminal, see `./gpggo.py --help`
  
```bash
./gpggo.py --message="Hello world" \
               --output="/tmp/output_file" \
               --encrypt_path="/tmp/remote_key.asc" \
               --sender="me@example.com" \
               --recipient="remote_person@example.com"
```
### Module
Import as a module into your application, see `pydoc3 gpggo` or rather your IDE autocomplete capability.

```python3
import gpggo
gpggo(message="Hello world",
        output="/tmp/output_file",
        encrypt="/tmp/remote_key.asc",
        sender="me@example.com",
        recipients="remote_person@example.com")
```

## Command list
All parameters are optional. When using as a module, all parameters may be set via `gpggo` attributes as defaults.

### Input / Output
  * **message (module only)**: Plain text message, file path or stream (ex: from open()) too.  
  * **message (CLI only)**: Plain text message.  
  * **input (CLI only)**: Path to the message file. (Alternative to `message` parameter.)  
  * **output**: Path to file to be written to (else the contents is returned).
  * **gnupg**: Home path to GNUPG rings else default ~/.gnupg is used
### Signing
  * **sign (module only)**: Sign the message. True or key-id.
  * **sign (CLI only)**: Sign the message, blank flag.
  * **sign-key (CLI only)**: Non-default key-id.  
  * **passphrase**: If signing key needs passphrase.
### Encrypting
  * **encrypt (module only)**: Recipients public key string or file path or stream (ex: from open()).
  * **encrypt (CLI only)**: Recipients public key string or 1/true/yes if the key should be in the ring from before. Put 0/false/no to disable `encrypt_path`.  
  * **recipients (module only)**: E-mail or list. If encrypting used so that we choose the key they will be able to decipher with.
  * **recipient (CLI only)**: If encrypting, we need recipient's e-mail so that we choose the key they will be able to decipher it.
  * **sender**: E-mail – needed to choose our key if encrypting. (In *module*, put False to explicitly omit.) 
  * **no-sender (CLI only)**: Declare we want to encrypt and never decrypt back.
  
See `./gpggo.py --help` for CLI arguments help or `pydoc3 gpggo` to see module arguments help.

## Examples

Sign the message.
```python3
gpggo(message="Hello world", sign=True)
```

Sign the message loaded from a file by standard pathlib library
```python3
from pathlib import Path
gpggo(message=Path("/tmp/message.txt"), sign=True)
```

Sign the message got from a file-stream
```python3
with open("/tmp/message.txt") as f:
    gpggo(message=f, sign=True)
```

Sign and encrypt the message so that's decryptable by keys for me@example.com and remote_person@example.com (that should already be loaded in the keyring).
```python3 
gpggo(message="Hello world", sign=True
        encrypt=True,
        sender="me@example.com",
        recipients="remote_person@example.com")
```

Sign and encrypt the message so that's decryptable by keys for me@example.com and remote_person@example.com (that get's imported to the keyring from the file).
```python3 
gpggo(message="Hello world", sign=True
        encrypt=Path("/tmp/remote_key.asc"),
        sender="me@example.com",
        recipients="remote_person@example.com")
```

Sign the message via different keyring.
```python3
gpggo(message="Hello world", sign=True, gnupg="/tmp/my-keyring/")
```

Sign the message with a key that needs passphrase.
```python3 
gpggo(message="Hello world", sign=True, passphrase="my-password")
```

Sign a message without signing by default turned previously on and having a default keyring path. Every `gpggo` call will honour these defaults. 
```python3 
gpggo.sign = True
gpggo.gnupg="/tmp/my-keyring/"
gpggo(message="Hello world")
```
