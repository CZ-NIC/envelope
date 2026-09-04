# Ciphering

## Cipher standard method
If neither *gpg* nor *smime* is specified explicitly, the method is auto-detected: envelope tries to parse whatever you passed to `sign`/`encrypt` as a PEM-encoded S/MIME private key (for signing) or certificate (for encrypting); if that parses, S/MIME is used, otherwise it falls back to GPG.

```python3
Envelope(message="Hello world", sign=True)  # no PEM key given → signed with the default GPG key
Envelope(message="Hello world", sign=Path("key.pem"))  # key.pem parses as an S/MIME key → signed with S/MIME
```

You may bypass the auto-detection and pick the method yourself:

  * **gpg**: True to prefer GPG over S/MIME or home path to GNUPG rings (otherwise default ~/.gnupg is used)
    * **--gpg [path]**
    * **.gpg(gnugp_home=True)**
    * **Envelope(gpg=True)**
  * **.smime**: Prefer S/MIME over GPG
    * **--smime**
    * **.smime()**
    * **Envelope(smime=True)**
## Signing
  * **sign**: Sign the message.
    * **`key`** parameter
        * GPG:
            * Blank (*CLI*) or True (*module*) for user default key
            * "auto" for turning on signing if there is a key matching to the "from" header
            * key ID/fingerprint
            * e-mail address of the identity whose key is to be signed with
            * [Any attainable contents](https://cz-nic.github.io/envelope/reference/overview/#any-attainable-contents) with the key to be signed with (will be imported into keyring)
        * S/MIME: [Any attainable contents](https://cz-nic.github.io/envelope/reference/overview/#any-attainable-contents) with key to be signed with. May contain signing certificate as well.
    * **--sign key**: (for `key` see above)
    * **--sign-path**: Filename with the From\'s private key. (Alternative to the `sign` parameter.)
    * **--passphrase**: Passphrase to the key if needed.
    * **--attach-key**: GPG: Blank for appending public key to the attachments when sending.
    * **--cert**: S/MIME: Certificate contents if not included in the key.
    * **--cert-path**: S/MIME: Filename with the From's private cert if cert not included in the key. (Alternative to the `cert` parameter.)
    * **.sign(key=True, passphrase=, attach_key=False, cert=None, key_path=None)**: Sign now (and you may specify the parameters). (For `key` see above.)
    * **.signature(key=True, passphrase=, attach_key=False, cert=None, key_path=None)**: Sign later (when launched with *.sign()*, *.encrypt()* or *.send()* functions
    * **Envelope(sign=key)**: (for `key` see above)
    * **Envelope(passphrase=)**: Passphrase to the signing key if needed.
    * **Envelope(attach_key=)**: If true, append GPG public key as an attachment when sending.
    * **Envelope(cert=)**: S/MIME: [Any attainable contents](https://cz-nic.github.io/envelope/reference/overview/#any-attainable-contents)
## Encrypting
  * **encrypt**:  Recipient GPG public key or S/MIME certificate to be encrypted with.
    * **`key`** parameter
        * GPG:
            * Blank (*CLI*) or True (*module*) to force encrypt with the user default keys (identities in the "from", "to", "cc" and "bcc" headers)
            * "auto" for turning on encrypting if there is a matching key for every recipient
            * key ID/fingerprint
            * e-mail address of the identity whose key is to be encrypted with
            * [Any attainable contents](https://cz-nic.github.io/envelope/reference/overview/#any-attainable-contents) with the key to be encrypted with (will be imported into keyring)
            * an iterable with the identities specified by key ID / fingerprint / e-mail address / raw key data
        * S/MIME [any attainable contents](https://cz-nic.github.io/envelope/reference/overview/#any-attainable-contents) with a certificate to be encrypted with or more in an iterable
    * **--encrypt [key]**: (for `key` see above) Put 0/false/no to disable `encrypt-path`.
    * **--encrypt-path** *(CLI only)*: Filename(s) with the recipient\'s public key(s). (Alternative to the `encrypt` parameter.)
    * **.encrypt(key=True, sign=, key_path=)**:
        * **`sign`** See signing, ex: you may specify boolean or default signing key ID/fingerprint or "auto" for GPG or [any attainable contents](https://cz-nic.github.io/envelope/reference/overview/#any-attainable-contents) with an S/MIME key + signing certificate.
        * **`key_path`**: Key/certificate contents (alternative to the `key` parameter)
    * **.encryption(key=True, key_path=)**: Encrypt later (when launched with *.sign()*, *.encrypt()* or *.send()* functions. If needed, in the parameters specify [any attainable contents](https://cz-nic.github.io/envelope/reference/overview/#any-attainable-contents) with GPG encryption key or S/MIME encryption certificate.
    * **Envelope(encrypt=key)**: (for `key` see above)
    ```bash
    # message gets encrypted for multiple S/MIME certificates
    envelope --smime --encrypt-path recipient1.pem recipient2.pem --message "Hello"

    # message gets encrypted with the default GPG key
    envelope  --message "Encrypted GPG message!" --subject "Secret subject will not be shown" --encrypt --from person@example.com --to person@example.com

    # message not encrypted for the sender (from Bash)
    envelope  --message "Encrypted GPG message!" --subject "Secret subject will not be shown" --encrypt receiver@example.com receiver2@example.com --from person@example.com --to receiver@example.com receiver2@example.com
    ```

    ```python3
    # message not encrypted for the sender (from Python)
    Envelope()
        .message("Encrypted GPG message!")
        .subject("Secret subject will not be shown")
        .from_("person@example.com")
        .to(("receiver@example.com", "receiver2@example.com"))
        .encrypt(("receiver@example.com", "receiver2@example.com"))
    ```

### GPG notes
* If the GPG encryption fails, it tries to determine which recipient misses the key.
* By default, GPG encrypts with the key of the **from** header recipient too.
* Key ID/fingerprint is internally ignored right now, GPG decides itself which key is to be used.
