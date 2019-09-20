# GPGGO

Quick layer over [python-gnupg](https://bitbucket.org/vinay.sajip/python-gnupg/src), [smtplib](https://docs.python.org/3/library/smtplib.html) and [email](https://docs.python.org/3/library/email.html?highlight=email#module-email) handling package. Their common usecases merged into single function. Want to sign a text and tired of forgetting how to do it right? You do not need to know everything about GPG, you do not have to bother with importing keys. Do not hassle with reconnecting SMTP server.
You insert a message and attachments and receive signed and/or encrypted output to the file or to your recipients' e-mail. 
Just single line of code. With the great help of the examples below.

If the encryption fails, it tries to determine what recipient misses the key.  

## Installation
If it's not already installed, you need `gpg` package if planning to sign/encrypt. Then, you can directly fetch the GitHub code.
```bash 
sudo apt install gpg
pip3 install git+https://github.com/CZ-NIC/gpggo.git  # without root use may want to use --user
```

## Usage:
As an example, let's produce in two equal ways an `output_file` with the encrypted "Hello world" content.
### CLI
Launch as a CLI application in terminal, see `./gpggo.py --help`
  
```bash
./gpggo.py --message "Hello world" \
               --output "/tmp/output_file" \
               --encrypt-path "/tmp/remote_key.asc" \
               --sender "me@example.com" \
               --recipients "remote_person@example.com"
```
### Module
Import as a module into your application, see `pydoc3 gpggo` or rather your IDE autocomplete capability.

```python3
import gpggo
gpggo(message="Hello world",
        output="/tmp/output_file",
        encrypt_path="/tmp/remote_key.asc",
        sender="me@example.com",
        recipients="remote_person@example.com")
```

## Command list
All parameters are optional. When using as a module, all parameters may be set via `gpggo` attributes as defaults.
Any fetchable content means plain text, bytes or stream (ex: from open()). In *module interface*, you may use Path object to the file. In *CLI interface*, additional flags are provided.         

### Input / Output
  * **message**: Any fetchable content
  * **input**: *(CLI only)* Path to the message file. (Alternative to `message` parameter.)  
  * **output**: Path to file to be written to (else the contents is returned).
  * **gnupg**: Home path to GNUPG rings else default ~/.gnupg is used
### Signing
  * **sign**: Sign the message. True (blank in *CLI*) for user default key or key-id-      
  * **passphrase**: If signing key needs passphrase.
### Encrypting
  * **encrypt**:  XXRecipient public key XXXor rather key-id? Can you know when string is key-id and when whole key? 
    * *(module only)*: Any fetchable content XXString or file path or stream (ex: from open()).
    * *(CLI only)*: String or 1/true/yes if the key should be in the ring from before. Put 0/false/no to disable `encrypt-path`.
  * **encrypt-file** *(CLI only)*: Recipient public key stored in a file path. (Alternative to `encrypt`.)  
  * **recipients**: E-mail or list. When encrypting, we use keys of these identities.
      ```bash
      ./gpggo.py --recipients first@example.com second@example.com --message "hello" 
      ```  
  * **sender**: E-mail – needed to choose our key if encrypting. (In *module*, put False to explicitly omit.) 
  * **no-sender** *(CLI only)*: Declare we want to encrypt and never decrypt back.
### Sending
  * **send**: Send the message to the recipients by e-mail. True (blank in *CLI*) to send now.
  * **subject**: Mail subject
  * **cc**: E-mail or their list
  * **bcc**: E-mail or their list
  * **reply-to**: E-mail to be replied to
  * **smtp**: SMTP server    
    * Input format may be in the following form:
        * `None` default localhost server used
        * `smtplib.SMTP` object
        * `list` or `tuple` having `host, [port, [username, password, [security]]]` parameters
            * ex: `./gpggo.py --smtp localhost 125 me@example.com` will set up host, port and username parameters
        * `dict` specifying {"host": ..., "port": ...}
            * ex: `./gpggo.py --smtp '{"host": "localhost"}'` will set up host parameter
    * Parameters: `security` parameter may have "starttls" value for calling `smtp.starttls()` connection security
  * **attachments** *(module only)*: Attachment or their list. Attachment is defined by any fetchable content, optionally in tuple with the file name to be used in the e-mail and/or mime type: `content [,name] [,mimetype]`
    ```python3p
    gpggo(attachments=[(Path("/tmp/file.txt"), "displayed-name.txt", "text/plain"), Path("/tmp/another-file.txt"])
    ```
  * **attachment** *(CLI only)*: Path to the attachment, followed by optional file name to be used and/or mime type. This parameter may be used multiple times.
    ```bash
    ./gpggo.py --attachment "/tmp/file.txt" "displayed-name.txt" "text/plain" --attachment "/tmp/another-file.txt"
    ```
    
See `./gpggo.py --help` for CLI arguments help or `pydoc3 gpggo` to see module arguments help.

## Examples

### Signing and encrypting

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

### Sending
Send an e-mail via module call.
```python3
gpggo(message="Hello world", send=True)
```

Send an e-mail via CLI and default SMTP server localhost on port 25.
```bash
./gpggo.py --recipient "user@example.org" --message "Hello world" --send
```

Send while having specified the SMTP server host, port, username, password.

```bash
./gpggo.py ----recipient "user@example.org" message "Hello world" --send --smtp localhost 123 username password 
```

Send while having specified the SMTP server through a dictionary.
```bash
./gpggo.py --recipient "user@example.org" --message "Hello world" --send --smtp '{"host": "localhost", "port": "123"}' 
```

Send while having specified the SMTP server via module call.
```python3
gpggo(message="Hello world", recipients="user@example.org", send=True, smtp={"host":"localhost"}) 
```

### Attachment
```python3
gpggo(attachment=Path("/tmp/file.txt"))

with open("/tmp/file.txt") as f:
    gpggo(attachment=f)
    
with open("/tmp/file.txt") as f:
    gpggo(attachment=(f, "filename.txt"))
```

### Complex example
Send an encrypted and signed message via the default SMTP server.
```bash
./gpggo.py --message "Hello world" --recipient "user@example.org" --sender "me@example.org" --subject "Test" --send --sign --encrypt --attachment /tmp/file.txt --attach /tmp/file2 application/gzip zipped-file.zip
```
