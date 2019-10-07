# Envelope

Quick layer over [python-gnupg](https://bitbucket.org/vinay.sajip/python-gnupg/src), [smime](https://pypi.org/project/smime/), [smtplib](https://docs.python.org/3/library/smtplib.html) and [email](https://docs.python.org/3/library/email.html?highlight=email#module-email) handling packages. Their common usecases merged into a single function. Want to sign a text and tired of forgetting how to do it right? You do not need to know everything about GPG or S/MIME, you do not have to bother with importing keys. Do not hassle with reconnecting SMTP server. Do not study various headers meanings to let your users unsubscribe via a URL.  
You insert a message and attachments and receive signed and/or encrypted output to the file or to your recipients' e-mail.  
Just single line of code. With the great help of the examples below.  

```python3
envelope("my message")
    .subject("hello world")
    .to("example@example.com")
    .attach(file_contents, filename="attached-file.txt")
    .smtp("localhost", 587, "user", "pass", "starttls")
    .signature()
    .send()
```

- [Installation](#installation)
- [Usage](#usage)
  * [CLI](#cli)
  * [Module: one-liner function](#module-one-liner-function)
  * [Module: fluent interface](#module-fluent-interface)
- [Documentation](#documentation)
  * [Command list](#command-list)
    + [Input / Output](#input--output)
    + [Cipher standard method](#cipher-standard-method)
    + [Signing](#signing)
    + [Encrypting](#encrypting)
    + [Sending](#sending)
      - [Specific headers](#specific-headers)
    + [Supportive](#supportive)
  * [Default values](#default-values)
  * [Converting object to str or bool](#converting-object-to-str-or-bool)
- [Examples](#examples)
  * [Signing and encrypting](#signing-and-encrypting)
  * [Sending](#sending-1)
  * [Attachment](#attachment)
  * [Complex example](#complex-example)
- [Related affairs](#related-affairs)
  * [Configure your SMTP](#configure-your-smtp)
  * [Configure your GPG](#configure-your-gpg)
  * [DNS validation tools](#dns-validation-tools)
    + [SPF](#spf)
    + [DKIM](#dkim)
    + [DMARC](#dmarc)


# Installation
* Install with a single command from [PyPi](https://pypi.org/project/envelope/)
```bash 
pip3 install envelope
```
* Or install current GitHub master
```bash
pip3 install git+https://github.com/CZ-NIC/envelope.git
```
* Or just download the project and launch `./envelope.py`
* If planning to send e-mails, prepare SMTP credentials or visit [Configure your SMTP](#configure-your-smtp) tutorial.
* If your e-mails are to be received outside your local domain, visit [DMARC](#dmarc) section.
* If planning to sign/encrypt with GPG, install the corresponding package and possibly see [Configure your GPG](#configure-your-gpg) tutorial.
```bash
sudo apt install gpg
```

# Usage
As an example, let's produce in three equal ways an `output_file` with the GPG-encrypted "Hello world" content.
## CLI
Launch as a CLI application in terminal, see `envelope --help`
  
```bash
envelope --message "Hello world" \
               --output "/tmp/output_file" \
               --sender "me@example.com" \
               --to "remote_person@example.com" \
               --encrypt-path "/tmp/remote_key.asc"
```
## Module: one-liner function
You can easily write a one-liner function that encrypts your code or sends an e-mail from within your application when imported as a module. See `pydoc3 envelope` or documentation below.

```python3
import envelope
envelope(message="Hello world",
        output="/tmp/output_file",
        sender="me@example.com",
        to="remote_person@example.com",
        encrypt="/tmp/remote_key.asc")
```

## Module: fluent interface
Comfortable way to create the structure if your IDE supports autocompletion.
```python3
import envelope
envelope().message("Hello world")\
    .output("/tmp/output_file")\
    .sender("me@example.com")\
    .to("remote_person@example.com")\
    .encrypt(key_path="/tmp/remote_key.asc")
```

Note: if autocompletion does not work, use **`from envelope import envelope`** instead of `import envelope`.  
(For example, Jupyter can autocomplete with `import envelope` but PyCharm cannot because it does not serves itself with a [running kernel](https://youtrack.jetbrains.com/issue/PY-38086#comment=27-3716668).)

# Documentation

Both `envelope --help` for CLI arguments help and `pydoc3 envelope` to see module arguments help should contain same information as here.

## Command list
All parameters are optional. 

* **--param** is used in CLI
* **envelope(param=)** is a one-liner argument
* **.param(value)** denotes a positional argument
* **.param(value=)** denotes a keyword argument
 
Any fetchable content means plain text, bytes or stream (ex: from open()). In *module interface*, you may use Path object to the file. In *CLI interface*, additional flags are provided.         

### Input / Output
  * **message**: Message / body text.
    * **--message**: String
    * **--input**: *(CLI only)* Path to the message file. (Alternative to `--message` parameter.)
    * **envelope(message=)**: Any fetchable content
    * **.message(text)**:  String or stream.
    * **.message(path=None)**: Path to the file.
    
    Equivalents for setting a string (in *Python* and in *Bash*).
    ```python3
    envelope(message="hello") == envelope().message("hello")
    ```
    ```bash
    envelope --message "hello"
    ``` 
    Equivalents for setting contents of a file (in *Python* and in *Bash*).
    ```python3
    from pathlib import Path
    envelope(message=Path("file.txt")) == envelope(message=open("file.txt")) == envelope.message(path="file.txt") 
    ```
    ```bash
    envelope --input file.txt
    ```
  * **output**: Path to file to be written to (else the contents is returned).
    * **--output**
    * **envelope(output=)**
    * **.output(output_file)**
### Cipher standard method
Note that if neither *gpg* nor *smime* is specified, we try to determine the method automatically.
  * **gpg**: True to prefer GPG over S/MIME or home path to GNUPG rings (otherwise default ~/.gnupg is used)
    * **--gpg [path]**
    * **envelope(gpg=True)**
    * **.gpg(path=True)**
  * **.smime**: Prefer S/MIME over GPG
    * **--smime**
    * **envelope(smime=True)**
    * **.smime()**
### Signing
  * **sign**: Sign the message.
    * **--sign**: Blank for user default key or key ID/fingerprint.
    * **--passphrase**: Passphrase to the key if needed.
    * **--attach-key**: Blank for appending public key to the attachments when sending.
    * **envelope(sign=)**: True for user default key or key ID/fingerprint.
    * **envelope(passphrase=)**: Passphrase to the key if needed.
    * **envelope(attach_key=)**: Append public key to the attachments when sending.
    * **.sign(key=, passphrase=, attach_key=False)**: Sign now (and you may specify the parameters)        
    * **.signature(key=, passphrase=, attach_key=False)**: Sign later (when launched with *.sign()*, *.encrypt()* or *.send()* functions
### Encrypting
If the GPG encryption fails, it tries to determine which recipient misses the key.

  * **encrypt**:  Recipient GPG public key or S/MIME certificate to be encrypted with. 
    * **--encrypt**: Key string or blank or 1/true/yes if the key should be in the ring from before. Put 0/false/no to disable `encrypt-file`.
    * **--encrypt-file** *(CLI only)*: Recipient public key stored in a file path. (Alternative to `--encrypt`.)  
    * **envelope(encrypt=)**: Any fetchable content
    * **.encrypt(sign=, key=, key_path=)**: With *sign*, you may specify boolean or default signing key ID/fingerprint. If import needed, put your encrypting key contents to *key* or path to the key contents file in *key_path*.
    * **.encryption(key=, key_path=)**: Encrypt later (when launched with *.sign()*, *.encrypt()* or *.send()* functions. 
  * **to**: E-mail or list. When encrypting, we use keys of these identities.
    * **--to**: One or more e-mail addresses.
    * **envelope(to=)**: E-mail or their list.
    * **.to(email_or_list)**:
      ```bash
      envelope --to first@example.com second@example.com --message "hello" 
      ```  
  * **sender**: E-mail – needed to choose our key if encrypting.
    * **--sender** E-mail
    * **--no-sender** Declare we want to encrypt and never decrypt back.
    * **--from** Alias for *--sender*
    * **envelope(sender=)**: Sender e-mail or False to explicitly omit. When encrypting without sender, we do not use their key so that we will not be able to decipher again.
    * **.sender(email)**: E-mail or False.
    * **.from_(email)**: an alias for *.sender*
### Sending
  * **send**: Send the message to the recipients by e-mail. True (blank in *CLI*) to send now or False to print out debug information.
    * **--send**
    * **envelope(send=)**
    * **.send(send=True, sign=None, encrypt=None)**
        * *send*: True to send now. False (or 0/false/no in *CLI*) to print debug information.
    
    ```bash
    $ envelope --to "user@example.org" --message "Hello world" --send 0
    ****************************************************************************************************
    Have not been sent from  to user@example.org
    
    Content-Type: text/html; charset="utf-8"
    Content-Transfer-Encoding: 7bit
    MIME-Version: 1.0
    Subject:
    From:
    To: user@example.org
    Date: Mon, 07 Oct 2019 16:13:37 +0200
    Message-ID: <157045761791.29779.5279828659897745855@...>
    
    Hello world
    ```
  * **subject**: Mail subject. Gets encrypted with GPG, stays visible with S/MIME.
    * **--subject**
    * **envelope(subject=)**
    * **.subject(text)**
  * **cc**: E-mail or their list
    * **--cc**
    * **envelope(cc=)**
    * **.cc(email_or_list)**
  * **bcc**: E-mail or their list
    * **--bcc**
    * **envelope(bcc=)**
    * **.bcc(email_or_list)**
  * **reply-to**: E-mail to be replied to. The field is not encrypted.
    * **--reply-to**
    * **envelope(reply_to=)**
    * **.reply_to(email)**
  * **smtp**: SMTP server
    * **--smtp**
    * **envelope(smtp=)**
    * **.smtp(host="localhost", port=25, user=, password=, security=)**
    * Parameters:
        * `host` may include hostname or any of the following input formats (ex: path to an INI file or a `dict`)
        * `security` parameter may have "starttls" value for calling `smtp.starttls()` connection security
    * Input format may be in the following form:
        * `None` default localhost server used
        * `smtplib.SMTP` object
        * `list` or `tuple` having `host, [port, [username, password, [security]]]` parameters
            * ex: `envelope --smtp localhost 125 me@example.com` will set up host, port and username parameters
        * `dict` specifying {"host": ..., "port": ...}
            * ex: `envelope --smtp '{"host": "localhost"}'` will set up host parameter
        * `str` hostname or path to an INI file (existing file, ending at `.ini`, with the section [SMTP])
            ```ini
            [SMTP]
            host = example.com
            port = 587
            security = starttls
            ```
    * Do not fear to pass the `smtp` in a loop, we make just a single connection to the server. If timed out, we attempt to reconnect once.
    ```python3
    smtp = localhost, 25
    for mail in mails:
        envelope(...).smtp(smtp).send()
    ```
  * **attachments**
    * **--attachment**: Path to the attachment, followed by optional file name to be used and/or mime type. This parameter may be used multiple times.
    ```bash
    envelope --attachment "/tmp/file.txt" "displayed-name.txt" "text/plain" --attachment "/tmp/another-file.txt"
    ```
    * **gpggp(attachments=)**: Attachment or their list. Attachment is defined by any fetchable content, optionally in tuple with the file name to be used in the e-mail and/or mime type: `content [,name] [,mimetype]`
    ```python3
    envelope(attachments=[(Path("/tmp/file.txt"), "displayed-name.txt", "text/plain"), Path("/tmp/another-file.txt"])
    ```    
    * **.attach(attachment_or_list=, path=, mimetype=, filename=)**: Three different usages.
        * **.attach(attachment_or_list=, mimetype=, filename=)**: You can put any fetchable content in *attachment_or_list* and optionally mimetype or displayed filename.
        * **.attach(path=, mimetype=, filename=)**: You can specify path and optionally mimetype or displayed filename.
        * **.attach(attachment_or_list=)**: You can put a list of attachments.
    ```python3
    envelope().attach(path="/tmp/file.txt").attach(path="/tmp/another-file.txt")
    ```
    * **headers**: Any custom headers (these will not be encrypted with GPG nor S/MIME)
        * **--header name value** (may be used multiple times)
        * **envelope(headers=[(name, value)])**
        * **.header(name, value)**
        
        Equivalent headers:
        ```bash
        envelope --header X-Mailer my-app
        ```
        
        ```python3
        envelope(headers=[("X-Mailer", "my-app")])
        envelope().header("X-Mailer", "my-app")
        ```                
#### Specific headers
These helpers are available via fluent interface.
    
* **.list_unsubscribe(uri=None, one_click=False, web=None, email=None)**: You can specify either url, email or both.
    * **.list_unsubscribe(uri)**: We try to determine whether this is e-mail and prepend brackets and 'https:'/'mailto:' if needed. Ex: `me@example.com?subject=unsubscribe`, `example.com/unsubscribe`, `<https://example.com/unsubscribe>`
    * **.list_unsubscribe(email=)**: E-mail address. Ex: `me@example.com`, `mailto:me@example.com`
    * **.list_unsubscribe(web=, one_click=False)**: Specify URL. Ex: `example.com/unsubscribe`, `http://example.com/unsubscribe`. If `one_click=True`, rfc8058 List-Unsubscribe-Post header is added. This says user can unsubscribe with a single click that is realized by a POST request in order to prevent e-mail scanner to access the unsubscribe page by mistake. A 'https' url must be present.

    ```python3
    # These will produce:
    # List-Unsubscribe: <https://example.com/unsubscribe>
    envelope().list_unsubscribe("example.com/unsubscribe")
    envelope().list_unsubscribe(web="example.com/unsubscribe")
    envelope().list_unsubscribe("<https://example.com/unsubscribe>")
    
    # This will produce:
    # List-Unsubscribe: <https://example.com/unsubscribe>, <mailto:me@example.com?subject=unsubscribe>
    envelope().list_unsubscribe("example.com/unsubscribe", mail="me@example.com?subject=unsubscribe")
    ```    
    
* **.auto_submitted**: 
    * **.auto_submitted(val="auto-replied")**: Direct response to another message by an automatic process. 
    * **.auto_submitted.auto_generated()**: automatic (often periodic) processes (such as UNIX "cron jobs") which are not direct responses to other messages
    * **.auto_submitted.no()**: message was originated by a human

```python3
envelope().auto_submitted()  # mark message as automatic        
envelope().auto_submitted.no()  # mark message as human produced
```    
### Supportive
  * **check**: Check SMTP connection and returns True/False if succeeded. Tries to find SPF, DKIM and DMARC DNS records depending on the sender's domain and print them out.
    * **--check**
    * **.check()**
    
    ```bash
    $ envelope --smtp localhost 25 --sender me@example.com 
    SPF found on the domain example.com: v=spf1 -all
    See: dig -t SPF example.com && dig -t TXT example.com
    DKIM found: ['v=DKIM1; g=*; k=rsa; p=...']
    Could not spot DMARC.
    Trying to connect to the SMTP...
    Check succeeded.
    ```
    
## Default values

In *module* interface, you may set the defaults when accessing `envelope.default` instance. 

```python3
envelope.default.subject("Test subject").signature()
envelope("Hello")  # this message has a default subject and is signed by default when sent
```

## Converting object to str or bool

When successfully signing, encrypting or sending, object is resolvable to True and signed text / produced e-mail could be obtained via str().

```python3
o = envelope("message", sign=True)
str(o)  # signed text
bool(o)  # True
```

# Examples

## Signing and encrypting

Sign the message.
```python3
envelope(message="Hello world", sign=True)
```

Sign the message loaded from a file by standard pathlib library
```python3
from pathlib import Path
envelope(message=Path("/tmp/message.txt"), sign=True)
```

Sign the message got from a file-stream
```python3
with open("/tmp/message.txt") as f:
    envelope(message=f, sign=True)
```

Sign and encrypt the message so that's decryptable by keys for me@example.com and remote_person@example.com (that should already be loaded in the keyring).
```python3 
envelope(message="Hello world", sign=True
        encrypt=True,
        sender="me@example.com",
        to="remote_person@example.com")
```

Sign and encrypt the message so that's decryptable by keys for me@example.com and remote_person@example.com (that get's imported to the keyring from the file).
```python3 
envelope(message="Hello world", sign=True
        encrypt=Path("/tmp/remote_key.asc"),
        sender="me@example.com",
        to="remote_person@example.com")
```

Sign the message via different keyring.
```python3
envelope(message="Hello world", sign=True, gnupg="/tmp/my-keyring/")
```

Sign the message with a key that needs passphrase.
```python3 
envelope(message="Hello world", sign=True, passphrase="my-password")
```

Sign a message without signing by default turned previously on and having a default keyring path. Every `envelope` call will honour these defaults. 
```python3 
envelope.default.signature(True).gnupghome("/tmp/my-keyring")
envelope(message="Hello world")
```

## Sending
Send an e-mail via module call.
```python3
envelope(message="Hello world", send=True)
```

Send an e-mail via CLI and default SMTP server localhost on port 25.
```bash
envelope --to "user@example.org" --message "Hello world" --send
```

Send while having specified the SMTP server host, port, username, password.

```bash
envelope --to "user@example.org" message "Hello world" --send --smtp localhost 123 username password 
```

Send while having specified the SMTP server through a dictionary.
```bash
envelope --to "user@example.org" --message "Hello world" --send --smtp '{"host": "localhost", "port": "123"}' 
```

Send while having specified the SMTP server via module call.
```python3
envelope(message="Hello world", to="user@example.org", send=True, smtp={"host":"localhost"}) 
```

## Attachment
You can attach a file in many different ways. Pick the one that suits you the best.
```python3
envelope(attachment=Path("/tmp/file.txt"))  # filename will be 'file.txt'

with open("/tmp/file.txt") as f:
    envelope(attachment=f)  # filename will be 'file.txt'
    
with open("/tmp/file.txt") as f:
    envelope(attachment=(f, "filename.txt"))
    
envelope().attach(path="/tmp/file.txt",filename="filename.txt")
```

## Complex example
Send an encrypted and signed message via the default SMTP server, via all three interfaces.
```bash
# CLI interface
envelope --message "Hello world" --to "user@example.org" --sender "me@example.org" --subject "Test" --sign --encrypt --attachment /tmp/file.txt --attach /tmp/file2 application/gzip zipped-file.zip --send
```
```python3
# one-liner interface
from pathlib import Path
envelope().message("Hello world").to("user@example.org").sender("me@example.org").subject("Test").signature().encryption().attach(path="/tmp/file.txt").attach(Path("/tmp/file2"), "application/gzip", "zipped-file.zip").send()

# fluent interface
envelope(message="Hello world", to="user@example.org", sender="me@example.org", subject="Test", sign=True, encrypt=True, attachments=[(Path("/tmp/file.txt"), (Path("/tmp/file2"), "application/gzip", "zipped-file.zip")], send=True)
```

# Related affairs
Sending an e-mail does not mean it will be received. Sending it successfully through your local domain does not mean a public mailbox will accept it as well. If you are not trustworthy enough, your e-mail may not even appear at the recipient's spam bin, it can just be discarded without notice. 

## Configure your SMTP
It is always easier if you have an account on an SMTP server the application is able to send e-mails with. If it is not the case, various SMTP server exist but as a quick and non-secure solution, I've tested [bytemark/smtp](https://hub.docker.com/r/bytemark/smtp/) docker image that allows you to start up a SMTP server by a single line.

```bash
docker run --network=host --restart always -d bytemark/smtp   # starts open port 25 on localhost
envelope --message "SMTP test" --from [your e-mail] --to [your e-mail] --smtp localhost 25 --send
```


## Configure your GPG
In order to sign messages, you need a private key. Let's pretend a usecase when your application will run under `www-data` user and GPG sign messages through the keys located at: `/var/www/.gnupg`. You have got a SMTP server with an e-mail account the application may use.
```bash 
GNUPGHOME=/var/www/.gnupg sudo -H -u www-data gpg --full-generate-key  # put application e-mail your are able to send the e-mail from]
# if the generation fails now because you are on a remote terminal, you may want to change temporarily the ownership of the terminal by the following command: 
# sudo chown www-data $(tty)  # put it back afterwards
GNUPGHOME=/var/www/.gnupg sudo -H -u www-data gpg --list-secret-keys  # get key ID
GNUPGHOME=/var/www/.gnupg sudo -H -u www-data gpg --send-keys [key ID]  # now the world is able to pull the key from a global webserver when they receive an e-mail from you
GNUPGHOME=/var/www/.gnupg sudo -H -u www-data envelope --message "Hello world" --subject "GPG signing test" --sign [key ID] --from [application e-mail] --to [your e-mail] --send  # you now receive e-mail and may import the key and set the trust to the key
```

It takes few hours to a key to propagate. If the key cannot be imported in your e-mail client because not found on the servers, try in the morning again or check the online search form at http://hkps.pool.sks-keyservers.net

XXX vystavte KEY id na webu. Nebo jak se to doporučuje?

## DNS validation tools
This is just a short explanation on these anti-spam mechanisms so that you can take basic notion what is going on.

Every time, the receiver should ask the sender's domain these questions over DNS.  

### SPF
The receiver asks the sender's domain: Do you allow the senders IP/domain to send the e-mail on your behalf?

Check your domain on SPF:
```bash
dig -t TXT example.com
``` 

### DKIM
The receiver asks the sender's domain: Give me the public key so that I may check the hash in the e-mail header that assert the message was composed by your private key. So that the e-mail comes trustworthy from you and nobody modified it on the way.

Check your domain on DKIM:
```bash
dig -t TXT [selector]._domainkey.example.com
``` 
You can obtain the `selector` from an e-mail message you received. Check the line `DKIM-Signature` and the value of the param `s`.
```
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/simple; d=example.com; s=default;
```

## DMARC
What is your policy concerning SPF and DKIM? What abuse address do you have?

Check your domain on DMARC:
```bash
dig -t TXT _dmarc.example.com
``` 