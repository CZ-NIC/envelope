# CHANGELOG

## 0.9.7 (unreleased)
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
    * if SMTP/INI file is given as a relative path and not found at CWD, we try program directory (useful when importing envelope as a library from another program)
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
