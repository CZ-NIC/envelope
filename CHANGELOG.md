# CHANGELOG

## 1.3 (unreleased)
- `.as_message` -> Message
- e-mail validation
- proper e-mail addresses handling: they can be in a string delimited by comma (or semicolon)
- text alternatives
- fix encoded headers

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
