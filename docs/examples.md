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
Envelope(message="Hello world", sign=True,
        encrypt=True,
        from_="me@example.com",
        to="remote_person@example.com")
```

Sign and encrypt the message so that's decryptable by keys for me@example.com and remote_person@example.com (that get's imported to the keyring from the file).
```python3
Envelope(message="Hello world", sign=True,
        encrypt=Path("/tmp/remote_key.asc"),
        from_="me@example.com",
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

Sign a message with signing by default turned previously on and having a default keyring path. Every `factory` call will honour these defaults.
```python3
factory = Envelope().signature(True).gpg("/tmp/my-keyring").copy
factory().(message="Hello world")
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
Envelope(attachment=Path("/tmp/file.txt"))  # file name will be 'file.txt'

with open("/tmp/file.txt") as f:
    Envelope(attachment=f)  # file name will be 'file.txt'

with open("/tmp/file.txt") as f:
    Envelope(attachment=(f, "filename.txt"))

Envelope().attach(path="/tmp/file.txt", name="filename.txt")
```

## Inline images
The only thing you have to do is to set the `inline=True` parameter of the attachment. Then, you can reference the image from within your message, with the help of `cid` keyword. For more details, see *attachments* in the [Sending](#sending) section.
```python3
(Envelope()
    .attach(path="/tmp/file.jpg", inline=True)
    .message("Hey, this is an inline image: <img src='cid:file.jpg' />"))
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
