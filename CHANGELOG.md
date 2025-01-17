# CHANGELOG

## 2.1.0 (2025-01-17)
- reworked s/mime cryptography

## 2.0.4 (2024-07-18)
- resilience against missing libmagic (useful on a contained environment)
- better SMTP retries #35
- better typing #31
- fix: attachment included while signing only (without sending)

## 2.0.3 (2024-01-03)
- fix: loading headers not encoded with utf-8
- fix: better S/MIME detection #29
- drop Python 3.9 support
- SMTP HELO FQDN

## 2.0.2 (2022-11-25)
- experimental [XARF](http://xarf.org/) reports reading
- disguised addresses parsing

## 2.0.1 (2022-11-21)
- fix #24 stable locale
- allow `file-magic` instead of `python-magic` package be installed on the system (#25)
- fix GPG signing when attaching file with name longer than 34 chars (#19)

## 2.0.0 (2022-05-04)
- CHANGED: `Envelope(sender=).sender()` alias REMOVED because to the unambiguous naming clash between the `From` and the `Sender` e-mail header. Use `Envelope().from_(...)` and `Envelope().header("Sender", ...)` instead. Pity that 'from' is a reserved keyword, "from_" looks bad.
- CHANGED: `Envelope.default` instance REMOVED because explicit is better than implicit. For setting defaults use `Envelope().copy()` instead
- CHANGED: explicitly specifying encryption keys prevents encrypting for other recipients
  - GPG encryption for arbitrary keys only possible #9 #14
- CHANGED: Optional parameter "email_or_list" renamed to "email_or_more" (methods `to` and friends)
  - When setting recipients, apart from list other iterables (tuple, generator, set, ...) may be used
- fix: when signing key fails, do not sign with the default GPG private key
- S/MIME insecure Rand PRNG removed #18

## 1.5.4 (2022-04-04)
- disable validate_email module blacklist updater #17
- SMTP envelope MAIL FROM address #16
- SMTP exposes timeout #20 , attempts, delay
- SMTP re-connect on every error #21
- smtp.quit() exposed #5

## 1.5.3 (2021-08-02)
- group syntax is no more reported as erroneous (ex: undisclosed-recipients:;)

## 1.5.2 (2021-06-02)
- better invalid header loading (ex: invalid charset in the content type header)
- SMTP connection uses `ssl.create_default_context()` by default

## 1.5.1 (2021-03-04)
- choose subject text placeholder while PGP encrypting
- fix sending e-mail without From if deliberately set to False (regression)

## 1.5 (2021-02-09)
– Address properties are "" if empty (handy when comparing strings)
- replace invalid characters when loading (the way the e-mail clients behave)
- headers truly case-insensitive when loading
- `.from_()` and `.sender()` truly return an `Address` even if not set (and then the Address is empty)
- fix: the internal cache correctly regenerated
- message is internally held in bytes -> helpful error message when charset fails

## 1.4 (2021-01-23)
- exposed Address
- Address casefold method and `user` and `host` properties
- loading ignores invalid headers (and prints out a warning)

## 1.3.3 (2021-01-21)
- fix case-insensitive header loading
- fix non-latin chars in header loading

## 1.3.2 (2020-10-26)
- fix charset for base64 encoded content
- fix the default encoding while casting an attachment to string

## 1.3 (2020-10-05)
- CHANGED:
    * `.attach(filename=)` renamed to `.attach(name=)`
    * `--attachment` renamed to `--attach`
    *  `.to()`, `.cc()`, `.bcc()`, `.from_()`, `.sender()`, `.reply_to()`, `.recipients()` now return an `Address` object(s), not `str`
- `.as_message` -> Message
- e-mail validation
- proper e-mail addresses handling: they can be in a string delimited by comma (or semicolon)
- text alternatives
- fix encoded headers
- fix attainable contents fetching
- embedding inline images
- loading parses attachments and decrypts
- contacts might be cleared (ex: to clear `To` header intuitively type `.to(False)`)
- `.attachments`, `--attachments [NAME]` -> read the list of the attachments
- preview returns nicely formatted headers

## 1.2 (2020-06-18)
- fix: smtplib.SMTP_SSL handshake operation timed out caught
- if a line is longer than 1000 characters, makes the message be transferred safely by bytes (which would not break up DKIM)
- when "Content-Transfer-Encoding" is set to "base64" or "quo-pri" and reading message, it gets decoded (useful when loading EML files `cat file.eml | envelope --message`)
- preview method available from CLI

## 1.1 (2020-05-30)
- fix: default object
- better EML files loading
- generic header manipulation (removing, adding multiple, mostly preserves order when loading)
- reply-to allows multiple addresses

## 1.0.0 (2020-05-28)
- CHANGED:
    * Envelope.__init__ parameters re-ordered
    * `from envelope import Envelope` is the only right way to import, `import envelope` no more supported (slightly longer, however better suits Python naming conventions)
- fix: --attach-key flag in CLI did not work
- auto-import GPG key from file
- auto-encrypt GPG possibility
- S/MIME multiple recipients
- "sender" works as an alias for "from_" if both are not used; otherwise standard "Sender" header is included
- .date(date) method allows turn off automatic Date header adding
- fix: object is modified whenever a parameter changes (ex: if user changes subject multiple times), not at send time
- `.message` has new aliases: `.body` and `.text` to facilitate the programmer's workflow because when autocomplete

## 0.9.9 (2020-02-10)
- smime dependency is optional – thus package can be installed directly without having swig library

## 0.9.8 (2020-01-27)
- set signing to "auto" for signing if there is a key matching to the "from" header
- preview method
- recipients method
- read subject(), message()
- load method

## 0.9.7 (2020-01-17)
- choose mime subtype (html or plain) + conditional conversion of line breaks to <br> #4
- experimental load function to create e-mail object from text templates
- fix: possibility to include own "Content-Type" into headers

## 0.9.6 (2020-01-14)
- fix: Subject tried to be re-set when no GPG neither S/MIME used

## 0.9.5 (2019-12-12)
- CHANGED:
    * `encrypt-file` changed to `encrypt-path` (to match the `encrypt_path` parameter of the `encrypt` method)
    * parameter swap from `.encrypt(sign=None, key=True)` to `.encrypt(key=True, sign=None)` due to S/MIME that does not take the key from the GPG keyring but needs the certificate to be specified every time.
- S\MIME
    * signing (`M2Crypto` instead of `smime` package)
    * insert subject while encrypting
- unit tests + travis build status
- SMTP
    * if SMTP/INI file is given as a relative path and not found at CWD, we try program directory (useful when importing Envelope as a library from another program)
    * TLS security supported
    * if security not defined, determined by port
- bash completion
- --quiet flag

## 0.9.4 (2019-12-03)
- fix launching with no flags (bare message erroneously tried to be GPG-signed by default)

## 0.9.3 (2019-11-30)
- attachment file not found caught
- output attached to the complex example in the README
- fix launched in a loop

## 0.9.2
- CLI: if nothing to do, assume parameters are a bone of an e-mail message to produce output
- check GPG signing failed
- fix GnuPG home
- fix encrypted subject
- SMTP supports INI file
- `check` will print out DNS information of the sender's domain
- CLI: metavar display names added
- attach_key flag added

## 0.9.1
- signing, encrypting, sending
- GPG, S/MIME support
- cli, one-liner, fluent interface
- SMTP reconnection
