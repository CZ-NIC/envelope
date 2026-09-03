# Envelope

[![Build Status](https://github.com/CZ-NIC/envelope/actions/workflows/run-unittest.yml/badge.svg)](https://github.com/CZ-NIC/envelope/actions) [![Downloads](https://static.pepy.tech/badge/envelope)](https://pepy.tech/project/envelope)

Quick layer over [python-gnupg](https://bitbucket.org/vinay.sajip/python-gnupg/src), [cryptography](https://github.com/pyca/cryptography), [M2Crypto](https://m2crypto.readthedocs.io/), [smtplib](https://docs.python.org/3/library/smtplib.html), [magic](https://pypi.org/project/python-magic/) and [email](https://docs.python.org/3/library/email.html?highlight=email#module-email) handling packages. Their common use cases merged into a single function. Want to sign a text and tired of forgetting how to do it right? You do not need to know everything about GPG or S/MIME, you do not have to bother with importing keys. Do not hassle with reconnecting to an SMTP server. Do not study various headers meanings to let your users unsubscribe via a URL.
You insert a message, attachments and inline images and receive signed and/or encrypted output to the file or to your recipients' e-mail.
Just single line of code. With the great help of the examples below.

```python3
Envelope("my message")
    .subject("hello world")
    .to("example@example.com")
    .attach(file_contents, name="attached-file.txt")
    .smtp("localhost", 587, "user", "pass", "starttls")
    .signature()
    .send()
```

```python3
# Inline image
Envelope("My inline image: <img src='cid:image.jpg' />")
    .attach(path="image.jpg", inline=True)

# Load a message and read its attachments
Envelope.load(path="message.eml").attachments()
# in bash: envelope --load message.eml --attachments
```

## Documentation

- [Installation](https://cz-nic.github.io/envelope/installation/) — PyPI/GitHub install, GPG/S-MIME prerequisites, bash completion.
- [Usage](https://cz-nic.github.io/envelope/usage/) — the CLI, the fluent interface and the one-liner module call.
- Reference — every setter, in all three interfaces:
    * [Overview](https://cz-nic.github.io/envelope/reference/overview/) — notation used below, "any attainable contents".
    * [Input / Output](https://cz-nic.github.io/envelope/reference/input-output/) — message, output.
    * [Recipients](https://cz-nic.github.io/envelope/reference/recipients/) — from, to, cc, bcc, reply-to, from_addr.
    * [Sending](https://cz-nic.github.io/envelope/reference/sending/) — send, subject, date, smtp, attachments, mime, headers.
    * [Ciphering](https://cz-nic.github.io/envelope/reference/ciphering/) — choosing GPG/S-MIME, signing, encrypting.
    * [Supportive](https://cz-nic.github.io/envelope/reference/supportive/) — recipients(), copy(), preview, check, load, Address.
    * [Experimental](https://cz-nic.github.io/envelope/reference/experimental/) — `_report()`, `_check_auth()`.
    * [Envelope object](https://cz-nic.github.io/envelope/reference/envelope-object/) — converting to str/bool, object equality.
- [Examples](https://cz-nic.github.io/envelope/examples/) — signing/encrypting, sending, attachments, inline images, a complex example.
- [Related affairs](https://cz-nic.github.io/envelope/related-affairs/) — configuring an SMTP server, GPG, S/MIME, and SPF/DKIM/DMARC.
- [Changelog](https://cz-nic.github.io/envelope/changelog/)
