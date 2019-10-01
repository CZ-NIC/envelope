# GPGGO

Quick layer over [python-gnupg](https://bitbucket.org/vinay.sajip/python-gnupg/src), [smtplib](https://docs.python.org/3/library/smtplib.html) and [email](https://docs.python.org/3/library/email.html?highlight=email#module-email) handling package. Their common usecases merged into a single function. Want to sign a text and tired of forgetting how to do it right? You do not need to know everything about GPG, you do not have to bother with importing keys. Do not hassle with reconnecting SMTP server. Do not study various headers meanings to let your users unsubscribe via a URL.
You insert a message and attachments and receive signed and/or encrypted output to the file or to your recipients' e-mail. 
Just single line of code. With the great help of the examples below.

If the encryption fails, it tries to determine which recipient misses the key.  

# Installation
If it's not already installed, you need `gpg` package if planning to sign/encrypt. Then, you can directly fetch the GitHub code.
```bash 
sudo apt install gpg
pip3 install git+https://github.com/CZ-NIC/gpggo.git  # without root use may want to use --user
```

# Usage:
As an example, let's produce in three equal ways an `output_file` with the encrypted "Hello world" content.
## CLI
Launch as a CLI application in terminal, see `./gpggo.py --help`
  
```bash
./gpggo.py --message "Hello world" \
               --output "/tmp/output_file" \
               --sender "me@example.com" \
               --recipients "remote_person@example.com" \
               --encrypt-path "/tmp/remote_key.asc"
```
## Module: one-liner function
You can easily write a one-liner function that encrypts your code or sends an e-mail from within your application when imported as a module. See `pydoc3 gpggo` or documentation below.

```python3
import gpggo
gpggo(message="Hello world",
        output="/tmp/output_file",
        sender="me@example.com",
        recipients="remote_person@example.com",
        encrypt="/tmp/remote_key.asc")
```

## Module: fluent interface
Comfortable way to create the structure if your IDE supports autocompletion.
```python3
import gpggo
gpggo().message("Hello world")\
    .output("/tmp/output_file")\
    .sender("me@example.com")\
    .recipient("remote_person@example.com")\
    .encrypt(key_path="/tmp/remote_key.asc")
```

Note: if you're in trouble, try importing `from gpggo import gppgo` instead of `import gpggo` 

# Documentation

Both `./gpggo.py --help` for CLI arguments help and `pydoc3 gpggo` to see module arguments help should contain same information as here.

## Command list
All parameters are optional. 

* **--param** is used in CLI
* **gpggo(param=)** is a one-liner argument
* **.param(value)** denotes a positional argument
* **.param(value=)** denotes a keyword argument
 
Any fetchable content means plain text, bytes or stream (ex: from open()). In *module interface*, you may use Path object to the file. In *CLI interface*, additional flags are provided.         

### Input / Output
  * **message**: Message / body text.
    * **--message**: String
    * **--input**: *(CLI only)* Path to the message file. (Alternative to `--message` parameter.)
    * **gpggo(message=)**: Any fetchable content
    * **.message(text)**:  String or stream.
    * **.message(path=None)**: Path to the file.
    
    Equivalents for setting a string.
    ```python3
    gpggo(message="hello") == gpggo().message("hello")
    ```
    ```bash
    ./gpggo --message "hello"
    ``` 
    Equivalents for setting contents of a file.
    ```python3
    from pathlib import Path
    gpggo(message=Path("file.txt")) == gpggo(message=open("file.txt")) == gpggo.message(path="file.txt") 
    ```
    ```bash
    ./gpggo --input file.txt
    ```
  * **output**: Path to file to be written to (else the contents is returned).
    * **--output**
    * **gpggo(output=)**
    * **.output(output_file)**
  * **gnupg**: Home path to GNUPG rings else default ~/.gnupg is used
### Signing
  * **sign**: Sign the message.
    * **--sign**: Blank for user default key or key-id.
    * **--passphrase**: Passphrase to the key if needed.
    * **gpggo(sign=)**: True for user default key or key-id.
    * **gpggo(passphrase=)**: Passphrase to the key if needed.
    * **.sign(key_id=, passphrase=)**: Sign now (and you may specify the parameters)
    * **.signature(key_id=, passphrase=)**: Sign later (when launched with *.sign()*, *.encrypt()* or *.send()* functions
### Encrypting
  * **encrypt**:  Recipient public key to be encrypted with. 
    * **--encrypt**: String for key-id or blank or 1/true/yes if the key should be in the ring from before. Put 0/false/no to disable `encrypt-file`.
    * **--encrypt-file** *(CLI only)*: Recipient public key stored in a file path. (Alternative to `--encrypt`.)  
    * **gpggo(encrypt=)**: Any fetchable content XXString or file path or stream (ex: from open()).
    * **.encrypt(sign=, key_id=, key_path=, key=)**: With *sign*, you may specify boolean or default signing key-id. Put your key-id to *key-id*, path to the key file in *key_path* or key contents to *key*.
    * **.encryption(key_id=, key_path=, key=)**: Encrypt later (when launched with *.sign()*, *.encrypt()* or *.send()* functions. 
  * **recipients**: E-mail or list. When encrypting, we use keys of these identities.
    * **--recipients**: One or more e-mail addresses.
    * **gpggo(recipients=)**: E-mail or their list.
    * **.recipient(email_or_list)**:
      ```bash
      ./gpggo.py --recipients first@example.com second@example.com --message "hello" 
      ```  
  * **sender**: E-mail – needed to choose our key if encrypting.
    * **--sender** E-mail
    * **--no-sender** Declare we want to encrypt and never decrypt back.
    * **gpggo(sender=)**: Sender e-mail or False to explicitly omit. When encrypting without sender, we do not use their key so that we will not be able to decipher again.
    * **.sender(e_mail)**: E-mail or False.
### Sending
  * **send**: Send the message to the recipients by e-mail. True (blank in *CLI*) to send now or False to print out debug information.
    * **--send**
    * **gpggo(send=)**
    * **.send(now=True)**
  * **subject**: Mail subject
    * **--subject**
    * **gpggo(subject=)**
    * **.subject(text)**
  * **cc**: E-mail or their list
    * **--cc**
    * **gpggo(cc=)**
    * **.cc(email_or_list)**
  * **bcc**: E-mail or their list
    * **--bcc**
    * **gpggo(bcc=)**
    * **.bcc(email_or_list)**
  * **reply-to**: E-mail to be replied to
    * **--reply-to**
    * **gpggo(reply_to=)**
    * **.reply_to(email)**
  * **smtp**: SMTP server
    * **--smtp**
    * **gpggo(smtp=)**
    * **.smtp(host="localhost", port=25, user=, password=, security=)**
    * Input format may be in the following form:
        * `None` default localhost server used
        * `smtplib.SMTP` object
        * `list` or `tuple` having `host, [port, [username, password, [security]]]` parameters
            * ex: `./gpggo.py --smtp localhost 125 me@example.com` will set up host, port and username parameters
        * `dict` specifying {"host": ..., "port": ...}
            * ex: `./gpggo.py --smtp '{"host": "localhost"}'` will set up host parameter
    * Parameters: `security` parameter may have "starttls" value for calling `smtp.starttls()` connection security        
  * **attachments**
    * **--attachment**: Path to the attachment, followed by optional file name to be used and/or mime type. This parameter may be used multiple times.
    ```bash
    ./gpggo.py --attachment "/tmp/file.txt" "displayed-name.txt" "text/plain" --attachment "/tmp/another-file.txt"
    ```
    * **gpggp(attachments=)**: Attachment or their list. Attachment is defined by any fetchable content, optionally in tuple with the file name to be used in the e-mail and/or mime type: `content [,name] [,mimetype]`
    ```python3
    gpggo(attachments=[(Path("/tmp/file.txt"), "displayed-name.txt", "text/plain"), Path("/tmp/another-file.txt"])
    ```    
    * **.attach(attachment_or_list=, path=, mimetype=, filename=)**: Three different usages.
        * **.attach(attachment_or_list=, mimetype=, filename=)**: You can put any fetchable content in *attachment_or_list* and optionally mimetype or displayed filename.
        * **.attach(path=, mimetype=, filename=)**: You can specify path and optionally mimetype or displayed filename.
        * **.attach(attachment_or_list=)**: You can put a list of attachments.
    * **headers**: Any custom headers (these will not be encrypted with GPG nor S/MIME)
        * **--header name value** (may be used multiple times)
        * **gpggo(headers=[(name, value)])**
        * **.header(name, value)**
        
        Equivalent headers:
        ```bash
        ./gpggo.py --header X-Mailer my-app
        ```
        
        ```python3
        gpggo(headers=[("X-Mailer", "my-app")])
        gpggo().header("X-Mailer", "my-app")
        ```                
#### Specific headers:
These helpers are available via fluent interface.
    
* **.list_unsubscribe(url_or_email=None, url=None, email=None, one_click=False)**: You can specify either url, email or both.
    * **.list_unsubscribe(url_or_email)**: We try to determine whether this is e-mail and prepend brackets and 'https:'/'mailto:' if needed. Ex: `me@example.com?subject=unsubscribe`, `example.com/unsubscribe`, `<https://example.com/unsubscribe>`
    * **.list_unsubscribe(email=)**: E-mail address. Ex: `me@example.com`, `mailto:me@example.com`
    * **.list_unsubscribe(url=, one_click=False)**: Specify URL. Ex: `example.com/unsubscribe`, `http://example.com/unsubscribe`. If `one_click=True`, rfc8058 List-Unsubscribe-Post header is added. This says user can unsubscribe with a single click that is realized by a POST request in order to prevent e-mail scanner to access the unsubscribe page by mistake. A 'https' url must be present.

    ```python3
    # These will produce:
    # List-Unsubscribe: <https://example.com/unsubscribe>
    gpggo().list_unsubscribe("example.com/unsubscribe")
    gpggo().list_unsubscribe(url="example.com/unsubscribe")
    gpggo().list_unsubscribe("<https://example.com/unsubscribe>")
    
    # This will produce:
    # List-Unsubscribe: <https://example.com/unsubscribe>, <mailto:me@example.com?subject=unsubscribe>
    gpggo().list_unsubscribe("example.com/unsubscribe", mail="me@example.com?subject=unsubscribe")
    ```    
    
* **.auto_submitted**: 
    * **.auto_submitted(val="auto-replied")**: Direct response to another message by an automatic process. 
    * **.auto_submitted.auto_generated()**: automatic (often periodic) processes (such as UNIX "cron jobs") which are not direct responses to other messages
    * **.auto_submitted.no()**: message was originated by a human

```python3
gpggo().auto_submitted()  # mark message as automatic        
gpggo().auto_submitted.no()  # mark message as human produced
```    
    
## Default values

In *module* interface, you may set the defaults when accessing `gpggo.default` instance. 

```python3
gpggo.default.subject("Test subject").signature()
gpggo("Hello")  # this message has a default subject and is signed by default when sent
```

## Converting object to str or bool

When successfully signing, encrypting or sending, object is resolvable to True and signed text / produced e-mail could be obtained via str().

```python3
o = gpggo("message", sign=True)
str(o)  # signed text
bool(o)  # True
```

# Examples

## Signing and encrypting

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
gpggo.default.signature(True).gnupghome("/tmp/my-keyring")
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

## Attachment
You can attach a file in many different ways. 
```python3
gpggo(attachment=Path("/tmp/file.txt"))  # filename will be 'file.txt'

with open("/tmp/file.txt") as f:
    gpggo(attachment=f)  # filename will be 'file.txt'
    
with open("/tmp/file.txt") as f:
    gpggo(attachment=(f, "filename.txt"))
    
gpggo().attach(path="/tmp/file.txt",filename="filename.txt")
```

## Complex example
Send an encrypted and signed message via the default SMTP server.
```bash
./gpggo.py --message "Hello world" --recipient "user@example.org" --sender "me@example.org" --subject "Test" --send --sign --encrypt --attachment /tmp/file.txt --attach /tmp/file2 application/gzip zipped-file.zip
```
