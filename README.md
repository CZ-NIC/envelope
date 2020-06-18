# Envelope

[![Build Status](https://travis-ci.org/CZ-NIC/envelope.svg?branch=master)](https://travis-ci.org/CZ-NIC/envelope)

Quick layer over [python-gnupg](https://bitbucket.org/vinay.sajip/python-gnupg/src), [M2Crypto](https://m2crypto.readthedocs.io/), [smtplib](https://docs.python.org/3/library/smtplib.html), [magic](https://pypi.org/project/python-magic/) and [email](https://docs.python.org/3/library/email.html?highlight=email#module-email) handling packages. Their common usecases merged into a single function. Want to sign a text and tired of forgetting how to do it right? You do not need to know everything about GPG or S/MIME, you do not have to bother with importing keys. Do not hassle with reconnecting SMTP server. Do not study various headers meanings to let your users unsubscribe via a URL.  
You insert a message and attachments and receive signed and/or encrypted output to the file or to your recipients' e-mail.  
Just single line of code. With the great help of the examples below.  

```python3
Envelope("my message")
    .subject("hello world")
    .to("example@example.com")
    .attach(file_contents, filename="attached-file.txt")
    .smtp("localhost", 587, "user", "pass", "starttls")
    .signature()
    .send()
```

- [Installation](#installation)
  * [Bash completion](#bash-completion)
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
  * [Choose ciphering method](#choose-ciphering-method)
    + [Configure your GPG](#configure-your-gpg)
    + [Configure your S/MIME](#configure-your-smime)
  * [DNS validation tools](#dns-validation-tools)
    + [SPF](#spf)
    + [DKIM](#dkim)
    + [DMARC](#dmarc)


# Installation
* If planning to use S/MIME, you should ensure some prerequisites:
```bash
sudo apt install swig
pip3 install M2Crypto
```
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

## Bash completion
1. Run: apt-get install bash-completion jq
2. Copy: extra/convey-autocompletion.bash to /etc/bash_completion.d/
3. Restart terminal

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
## Module: fluent interface
Comfortable way to create the structure if your IDE supports autocompletion.
```python3
from envelope import Envelope
Envelope().message("Hello world")\
    .output("/tmp/output_file")\
    .sender("me@example.com")\
    .to("remote_person@example.com")\
    .encrypt(key_path="/tmp/remote_key.asc")
```

## Module: one-liner function
You can easily write a one-liner function that encrypts your code or sends an e-mail from within your application when imported as a module. See `pydoc3 envelope` or documentation below.

```python3
from envelope import Envelope
Envelope(message="Hello world",
        output="/tmp/output_file",
        sender="me@example.com",
        to="remote_person@example.com",
        encrypt="/tmp/remote_key.asc")
```

# Documentation

Both `envelope --help` for CLI arguments help and `pydoc3 envelope` to see module arguments help should contain same information as here.

## Command list
All parameters are optional. 

* **--param** is used in CLI
* **.param(value)** denotes a positional argument
* **.param(value=)** denotes a keyword argument
* **Envelope(param=)** is a one-liner argument
 
Any attainable contents means plain text, bytes or stream (ex: from open()). In *module interface*, you may use Path object to the file. In *CLI interface*, additional flags are provided.         

### Input / Output
  * **message**: Message / body text.
    If no string is set, message gets read. Besides, when "Content-Transfer-Encoding" is set to "base64" or "quoted-printable", it gets decoded (useful when quickly reading an EML file content `cat file.eml | envelope --message`).
    * **--message**: String
    * **--input**: *(CLI only)* Path to the message file. (Alternative to `--message` parameter.)
    * **.message(text)**:  String or stream.
    * **.message(path=None)**: Path to the file.
    * **.body**: Alias of `.message`
    * **.text**: Alias of `.message`
    * **Envelope(message=)**: Any attainable contents
    
    Equivalents for setting a string (in *Python* and in *Bash*).
    ```python3
    Envelope(message="hello") == Envelope().message("hello")
    ```
    ```bash
    envelope --message "hello"
    ``` 
    Equivalents for setting contents of a file (in *Python* and in *Bash*).
    ```python3
    from pathlib import Path
    Envelope(message=Path("file.txt")) == Envelope(message=open("file.txt")) == Envelope.message(path="file.txt") 
    ```
    ```bash
    envelope --input file.txt
    ```
  * **output**: Path to file to be written to (else the contents is returned).
    * **--output**
    * **.output(output_file)**
    * **Envelope(output=)**
### Cipher standard method
Note that if neither *gpg* nor *smime* is specified, we try to determine the method automatically.
  * **gpg**: True to prefer GPG over S/MIME or home path to GNUPG rings (otherwise default ~/.gnupg is used)
    * **--gpg [path]**
    * **.gpg(gnugp_home=True)**
    * **Envelope(gpg=True)**
  * **.smime**: Prefer S/MIME over GPG
    * **--smime**
    * **.smime()**
    * **Envelope(smime=True)**
### Signing
  * **sign**: Sign the message.
    * **`key`** parameter
        * GPG: 
            * Blank (*CLI*) or True (*module*) for user default key
            * key ID/fingerprint
            * Any attainable contents with the key to be signed with (will be imported into keyring)
            * "auto" for turning on signing if there is a key matching to the "from" header
        * S/MIME: Any attainable contents with key to be signed with. May contain signing certificate as well.            
    * **--sign key**: (for `key` see above)
    * **--sign-path**: Filename with the sender\'s private key. (Alternative to `sign` parameter.)
    * **--passphrase**: Passphrase to the key if needed.
    * **--attach-key**: GPG: Blank for appending public key to the attachments when sending.
    * **--cert**: S/MIME: Certificate contents if not included in the key.
    * **--cert-path**: S/MIME: Filename with the sender's private cert if cert not included in the key. (Alternative to `cert` parameter.)
    * **.sign(key=True, passphrase=, attach_key=False, cert=None, key_path=None)**: Sign now (and you may specify the parameters). (For `key` see above.)
    * **.signature(key=True, passphrase=, attach_key=False, cert=None, key_path=None)**: Sign later (when launched with *.sign()*, *.encrypt()* or *.send()* functions
    * **Envelope(sign=key)**: (for `key` see above)        
    * **Envelope(passphrase=)**: Passphrase to the key if needed.
    * **Envelope(attach_key=)**: GPG: Append public key to the attachments when sending.
    * **Envelope(cert=)**: S/MIME: Any attainable contents.
### Encrypting
If the GPG encryption fails, it tries to determine which recipient misses the key.

  * **encrypt**:  Recipient GPG public key or S/MIME certificate to be encrypted with. 
    * **`key`** parameter
        * GPG:
            * Blank (*CLI*) or True (*module*) to force encrypt
            * key ID/fingerprint
            * Any attainable contents with the key to be encrypted with (will be imported into keyring)
            * "auto" for turning on encrypting if there is a matching key for every recipient
        * S/MIME any attainable contents with certificate to be encrypted with or their list
    * **--encrypt key**: (for `key` see above) Put 0/false/no to disable `encrypt-path`.
    * **--encrypt-path** *(CLI only)*: Filename(s) with the recipient\'s public key. (Alternative to `encrypt` parameter.)
    * **.encrypt(key=True, sign=, key_path=)**:
        * **`sign`** You may specify boolean or default signing key ID/fingerprint or "auto" for GPG or any attainable contents with S/MIME key + signing certificate.
        * **`key_path`**: Key/certificate contents (alternative to `key` parameter)
    * **.encryption(key=True, key_path=)**: Encrypt later (when launched with *.sign()*, *.encrypt()* or *.send()* functions. If needed, in the parameters specify Any attainable contents with GPG encryption key or S/MIME encryption certificate. 
    ```bash
    # message gets encrypted for multiple certificates
    envelope --smime --encrypt-path recipient1.pem recipient2.pem --message "Hello"
    ```
    * **Envelope(encrypt=)**: Any attainable contents
  * **to**: E-mail or list. When encrypting, we use keys of these identities.
    * **--to**: One or more e-mail addresses.
      ```bash
      envelope --to first@example.com second@example.com --message "hello" 
      ```  
    * **.to(email_or_list)**: If None, current list is returned.
    * **Envelope(to=)**: E-mail or their list.
  * **from**: E-mail – needed to choose our key if encrypting.    
    * **--from** E-mail
    * **--sender** Alias for *--from* if not set. Otherwise appends header "Sender".
    * **--no-sender** Declare we want to encrypt and never decrypt back.
    * **.from_(email)**: E-mail or False. If None, current `From` returned.
    * **.sender(email)**: E-mail or False – an alias for *.from_*, will fill up `From` header. If `From` has already been set, this will fill `Sender` header. If None, current `Sender` returned.
    * **Envelope(from_=)**: Sender e-mail or False to explicitly omit. When encrypting without sender, we do not use their key so that we will not be able to decipher again.       
    * **Envelope(sender=)** *(see --sender)*
    ```python3
    # These statement are identic.
    Envelope(from_ = "identity@example.com")    
    Envelope(sender = "identity@example.com")
  
    # This statement produces both From header and Sender header.
    Envelope(from_ = "identity@example.com", sender="identity2@example.com")        
    ```
### Sending
  * **send**: Send the message to the recipients by e-mail. True (blank in *CLI*) to send now or False to print out debug information.
    * **--send**
    * **.send(send=True, sign=None, encrypt=None)**
        * *send*: True to send now. False (or 0/false/no in *CLI*) to print debug information.
        * Returns the object back which converted to bool returns True if the message has been sent successfully.
    * **Envelope(send=)**
    
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
    * **.subject(text)**: If None, current subject returned.     
    * **Envelope(subject=)**
  * **cc**: E-mail or their list
    * **--cc**
    * **.cc(email_or_list)**: If None, current list returned.
    * **Envelope(cc=)**
  * **bcc**: E-mail or their list
    * **--bcc**
    * **.bcc(email_or_list)**: If None, current list returned.
    * **Envelope(bcc=)**
  * **reply-to**: E-mail to be replied to or their list. The field is not encrypted.
    * **--reply-to**
    * **.reply_to(email_or_list)**: If None, current list returned.
    * **Envelope(reply_to=)**
  * **date**:
    * **.date(date)** `str|False` Specify Date header (otherwise Date is added automatically). If False, the Date header will not be added automatically.
  * **smtp**: SMTP server
    * **--smtp**
    * **.smtp(host="localhost", port=25, user=, password=, security=)**
    * **Envelope(smtp=)**
    * Parameters:
        * `host` may include hostname or any of the following input formats (ex: path to an INI file or a `dict`)
        * `security` if not set, automatically set to `starttls` for port *587* and to `tls` for port *465*
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
            ```
    * Do not fear to pass the `smtp` in a loop, we make just a single connection to the server. If timed out, we attempt to reconnect once.
    ```python3
    smtp = localhost, 25
    for mail in mails:
        Envelope(...).smtp(smtp).send()
    ```
  * **attachments**
    * **--attachment**: Path to the attachment, followed by optional file name to be used and/or mime type. This parameter may be used multiple times.
    ```bash
    envelope --attachment "/tmp/file.txt" "displayed-name.txt" "text/plain" --attachment "/tmp/another-file.txt"
    ```
    * **.attach(attachment=, mimetype=, filename=, path=)**: Three different usages.
        * **.attach(attachment=, mimetype=, filename=)**: You can put any attainable contents of a single attachment into *attachment* and optionally add mime type or displayed file name.
        * **.attach(mimetype=, filename=, path=)**: You can specify path and optionally mime type or displayed file name.
        * **.attach(attachment=)**: You can put a list of attachments. The list may contain tuples: `contents [,mimetype/filename] [,mimetype/filename]`.
    ```python3
    Envelope().attach(path="/tmp/file.txt").attach(path="/tmp/another-file.txt")
    ```
    * **Envelope(attachments=)**: Attachment or their list. Attachment is defined by any attainable contents, optionally in tuple with the file name to be used in the e-mail and/or mime type: `contents [,mimetype/filename] [,mimetype/filename]`
    ```python3
    Envelope(attachments=[(Path("/tmp/file.txt"), "displayed-name.txt", "text/plain"), Path("/tmp/another-file.txt"])
    ```    
    * **mime**: Sets contents mime subtype: "**auto**" (default), "**html**" or "**plain**" for plain text. 
        Maintype is always set to "text".                 
        Set maintype to "text".  If a line is longer than 1000 characters, makes the message be transferred safely by bytes (otherwise these non-standard long lines might cause a transferring SMTP server to include line breaks and redundant spaces that might break up ex: DKIM signature).  
        In case of `Content-Type` header put to the message, **mime** section functionality **is skipped**.
        * **--mime SUBTYPE**
        * **.mime(subtype="auto", nl2br="auto")**
            * nl2br: True will append `<br>` to every line break in the HTML message. "auto": line breaks are changed only if there is no `<br` or `<p` in the HTML message,
        * **Envelope(mime=)**
    * **headers**: Any custom headers (these will not be encrypted with GPG nor S/MIME)
        * **--header name value** (may be used multiple times)
        * **.header(name, value=None, replace=False)**
            * `value` If None, returns value of the header or its list if the header was used multiple times. (Note that To, Cc, Bcc and Reply-To headers always return list.)
            * `replace` If True, any header of the `key` name are removed first and if `val` is None, the header is deleted. Otherwise another header of the same name is appended.
            ```python3
            Envelope().header("X-Mailer", "my-app").header("X-Mailer") # "my-app"
            Envelope().header("Generic-Header", "1") \
                      .header("Generic-Header", "2") \
                      .header("Generic-Header") # ["1", "2"]
            ```
        * **Envelope(headers=[(name, value)])**
        
        Equivalent headers: 
        ```bash
        envelope --header X-Mailer my-app
        ```
        
        ```python3
        Envelope(headers=[("X-Mailer", "my-app")])
        Envelope().header("X-Mailer", "my-app")
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
    Envelope().list_unsubscribe("example.com/unsubscribe")
    Envelope().list_unsubscribe(web="example.com/unsubscribe")
    Envelope().list_unsubscribe("<https://example.com/unsubscribe>")
    
    # This will produce:
    # List-Unsubscribe: <https://example.com/unsubscribe>, <mailto:me@example.com?subject=unsubscribe>
    Envelope().list_unsubscribe("example.com/unsubscribe", mail="me@example.com?subject=unsubscribe")
    ```    
    
* **.auto_submitted**: 
    * **.auto_submitted(val="auto-replied")**: Direct response to another message by an automatic process. 
    * **.auto_submitted.auto_generated()**: automatic (often periodic) processes (such as UNIX "cron jobs") which are not direct responses to other messages
    * **.auto_submitted.no()**: message was originated by a human

```python3
Envelope().auto_submitted()  # mark message as automatic        
Envelope().auto_submitted.no()  # mark message as human produced
```    
### Supportive
  * **.recipients()**: Return set of all recipients – To, Cc, Bcc
    * **.recipients(clear=True)**: All To, Cc and Bcc recipients are removed and the object is returned.
  * **.copy()**: Return deep copy of the instance to be used independently. 
  ```python3    
    factory = Envelope().cc("original@example.com").copy
    e1 = factory().to("to-1@example.com")
    e2 = factory().to("to-2@example.com").cc("additional@example.com")  # 

    print(e1.recipients())  # {'to-1@example.com', 'original@example.com'}
    print(e2.recipients())  # {'to-2@example.com', 'original@example.com', 'additional@example.com'}
```
  * Read message and subject by **.message()** and **.subject()**  
  * **preview**: Returns the string of the message or data as a human-readable text.
            Ex: whilst we have to use quoted-printable (as seen in __str__), here the output will be plain text.
    * **--preview**
    * **.preview()**
  * **check**: Check SMTP connection and returns True/False if succeeded. Tries to find SPF, DKIM and DMARC DNS records depending on the sender's domain and print them out.
    * **--check**
    * **.check()**
    
    ```bash
    $ envelope --smtp localhost 25 --sender me@example.com --check 
    SPF found on the domain example.com: v=spf1 -all
    See: dig -t SPF example.com && dig -t TXT example.com
    DKIM found: ['v=DKIM1; g=*; k=rsa; p=...']
    Could not spot DMARC.
    Trying to connect to the SMTP...
    Check succeeded.
    ```
 * **load**: **(experimental)**: Parse any attainable contents (including email.message.EmailMessage) like an EML file to build an Envelope object.
    * Still considered experimental: it cannot read an attachment which stays a mere part of the body, it cannot decrypt.
    * Note that if you will send this reconstructed message, you might not probably receive it due to the Message-ID duplication. Delete at least Message-ID header prior to re-sending. 
    * (*static*) **.load(message)**
        ```python3
       Envelope.load("Subject: testing message").subject()  # "testing message"
        ```
    * bash
        * allows use blank `--subject` or `--message` flags to display the 
        * **--load FILE**
            ```bash
            $ envelope --load email.eml
            Content-Type: text/plain; charset="utf-8"
            Content-Transfer-Encoding: 7bit
            MIME-Version: 1.0
            Subject: testing message
            
            Message body
          
            $ envelope --load email.eml --subject
            testing message          
            ```
        * (*bash*) piped in content XXX, envelope executable used with no argument    
            ```bash
            $ echo "Subject: testing message" | envelope
            Content-Type: text/plain; charset="utf-8"
            Content-Transfer-Encoding: 7bit
            MIME-Version: 1.0
            Subject: testing message
           
           $ cat email.eml | envelope
           ```
   
## Default values

In *module* interface, you may set the defaults when accessing `Envelope.default` instance. 

```python3
Envelope.default.subject("Test subject").signature()
Envelope("Hello")  # this message has a default subject and is signed by default when sent
```

## Converting object to str or bool

When successfully signing, encrypting or sending, object is resolvable to True and signed text / produced e-mail could be obtained via str().

```python3
o = Envelope("message", sign=True)
str(o)  # signed text
bool(o)  # True
```

# Examples

## Signing and encrypting

Sign the message.
```python3
Envelope(message="Hello world", sign=True)
```

Sign the message loaded from a file by standard pathlib library
```python3
from pathlib import Path
Envelope(message=Path("/tmp/message.txt"), sign=True)
```

Sign the message got from a file-stream
```python3
with open("/tmp/message.txt") as f:
    Envelope(message=f, sign=True)
```

Sign and encrypt the message so that's decryptable by keys for me@example.com and remote_person@example.com (that should already be loaded in the keyring).
```python3 
Envelope(message="Hello world", sign=True
        encrypt=True,
        sender="me@example.com",
        to="remote_person@example.com")
```

Sign and encrypt the message so that's decryptable by keys for me@example.com and remote_person@example.com (that get's imported to the keyring from the file).
```python3 
Envelope(message="Hello world", sign=True
        encrypt=Path("/tmp/remote_key.asc"),
        sender="me@example.com",
        to="remote_person@example.com")
```

Sign the message via different keyring.
```python3
Envelope(message="Hello world", sign=True, gnupg="/tmp/my-keyring/")
```

Sign the message with a key that needs passphrase.
```python3 
Envelope(message="Hello world", sign=True, passphrase="my-password")
```

Sign a message without signing by default turned previously on and having a default keyring path. Every `Envelope` call will honour these defaults. 
```python3 
Envelope.default.signature(True).gnupghome("/tmp/my-keyring")
Envelope(message="Hello world")
```

## Sending
Send an e-mail via module call.
```python3
Envelope(message="Hello world", send=True)
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
Envelope(message="Hello world", to="user@example.org", send=True, smtp={"host":"localhost"}) 
```

## Attachment
You can attach a file in many different ways. Pick the one that suits you the best.
```python3
Envelope(attachment=Path("/tmp/file.txt"))  # filename will be 'file.txt'

with open("/tmp/file.txt") as f:
    Envelope(attachment=f)  # filename will be 'file.txt'
    
with open("/tmp/file.txt") as f:
    Envelope(attachment=(f, "filename.txt"))
    
Envelope().attach(path="/tmp/file.txt",filename="filename.txt")
```

## Complex example
Send an encrypted and signed message (GPG) via the default SMTP server, via all three interfaces.
```bash
# CLI interface
envelope --message "Hello world" --from "me@example.org" --to "user@example.org" --subject "Test" --sign --encrypt -a /tmp/file.txt -a /tmp/file2 application/gzip zipped-file.zip --send
```
```python3
from pathlib import Path
from envelope import Envelope

# fluent interface
Envelope().message("Hello world").from_("me@example.org").to("user@example.org").subject("Test").signature().encryption().attach(path="/tmp/file.txt").attach(Path("/tmp/file2"), "application/gzip", "zipped-file.zip").send()

# one-liner interface
Envelope("Hello world", "me@example.org", "user@example.org", "Test", sign=True, encrypt=True, attachments=[(Path("/tmp/file.txt"), (Path("/tmp/file2"), "application/gzip", "zipped-file.zip")], send=True)
```

In the condition *me@example.com* private key for signing, *user@example.com* public key for encrypting and open SMTP server on *localhost:25* are available, change `--send` to `--send 0` (or `.send()` to `.send(False)` or `send=True` to `send=False`) to investigate the generated message that may be similar to the following output:
```bash
****************************************************************************************************
Have not been sent from me@example.org to user@example.org
Encrypted subject: Test
Encrypted message: b'Hello world'

Subject: Encrypted message
MIME-Version: 1.0
Content-Type: multipart/encrypted; protocol="application/pgp-encrypted";
 boundary="===============8462917939563016793=="
From: me@example.org
To: user@example.org
Date: Tue, 08 Oct 2019 16:16:18 +0200
Message-ID: <157054417817.4405.938581433237601455@promyka>

--===============8462917939563016793==
Content-Type: application/pgp-encrypted

Version: 1
--===============8462917939563016793==
Content-Type: application/octet-stream; name="encrypted.asc"
Content-Description: OpenPGP encrypted message
Content-Disposition: inline; filename="encrypted.asc"

-----BEGIN PGP MESSAGE-----

hQMOAyx1c9zl1h4wEAv+PmtwjQDt+4XCn8YQJ6d7kyrp2R7xzS3PQwOZ7e+HWJjY
(...)
RQ8QtLLEza+rs+1lgcPgdBZEHFpYpgDb0AUvYg9d
=YuqI
-----END PGP MESSAGE-----

--===============8462917939563016793==--
```

# Related affairs
Sending an e-mail does not mean it will be received. Sending it successfully through your local domain does not mean a public mailbox will accept it as well. If you are not trustworthy enough, your e-mail may not even appear at the recipient's spam bin, it can just be discarded without notice. 

## Configure your SMTP
It is always easier if you have an account on an SMTP server the application is able to send e-mails with. If it is not the case, various SMTP server exist but as a quick and non-secure solution, I've tested [bytemark/smtp](https://hub.docker.com/r/bytemark/smtp/) docker image that allows you to start up a SMTP server by a single line.

```bash
docker run --network=host --restart always -d bytemark/smtp   # starts open port 25 on localhost
envelope --message "SMTP test" --from [your e-mail] --to [your e-mail] --smtp localhost 25 --send
```

## Choose ciphering method

### Configure your GPG
In order to sign messages, you need a private key. Let's pretend a usecase when your application will run under `www-data` user and GPG sign messages through the keys located at: `/var/www/.gnupg`. You have got a SMTP server with an e-mail account the application may use.
```bash
ls -l $(tty)  # see current TTY owner
sudo chown www-data $(tty)  # if creating the key for a different user and generation fails, changing temporarily the ownership of the terminal might help (when handling passphrase, the agent opens the controlling terminal rather than using stdin/stdout for security purposes)
GNUPGHOME=/var/www/.gnupg sudo -H -u www-data gpg --full-generate-key  # put application e-mail you are able to send e-mails from
# sudo chown [USER] $(tty)  # you may set back the TTY owner
GNUPGHOME=/var/www/.gnupg sudo -H -u www-data gpg --list-secret-keys  # get key ID
GNUPGHOME=/var/www/.gnupg sudo -H -u www-data gpg --send-keys [key ID]  # now the world is able to pull the key from a global webserver when they receive an e-mail from you
GNUPGHOME=/var/www/.gnupg sudo -H -u www-data gpg --export [APPLICATION_EMAIL] | curl -T - https://keys.openpgp.org  # prints out the link you can verify your key with on `keys.openpgp.org` (ex: used by default by Thunderbird Enigmail; standard --send-keys method will not verify the identity information here, hence your e-mail would not be searchable)
GNUPGHOME=/var/www/.gnupg sudo -H -u www-data envelope --message "Hello world" --subject "GPG signing test" --sign [key ID] --from [application e-mail] --to [your e-mail] --send  # you now receive e-mail and may import the key and set the trust to the key
```

It takes few hours to a key to propagate. If the key cannot be imported in your e-mail client because not found on the servers, try in the morning again or check the online search form at http://hkps.pool.sks-keyservers.net.  
Put your fingerprint on the web or on the business card then so that everybody can check your signature is valid.

### Configure your S/MIME
If you are supposed to use S/MIME, you would probably be told where to take your key and certificate from. If planning to try it all by yourself, generate your `certificate.pem`.
 
* Either: Do you have private key?
```bash
openssl req -key YOUR-KEY.pem -nodes -x509 -days 365 -out certificate.pem  # will generate privkey.pem alongside
```
 
* Or: Do not you have private key? 
```bash
openssl req -newkey rsa:1024 -nodes -x509 -days 365 -out certificate.pem  # will generate privkey.pem alongside
```

Now, you may sign a message with your key and certificate. (However, the messages **will not be trustworthy** because no authority signed the certificate.) Give your friend the certificate so that they might verify the message comes from you. Receive a certificate from a friend to encrypt them a message with.
```
envelope --message "Hello world" --subject "S/MIME signing test" --sign-path [key file] --cert-path [certificate file] --from [application e-mail] --to [your e-mail] --send # you now receive e-mail
```

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
