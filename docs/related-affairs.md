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

Every time, the receiver should ask the From's domain these questions over DNS.

### SPF
The receiver asks the sender's domain: Do you allow the senders IP/domain to send the e-mail on your behalf? Is the IP/domain the mail originates from enlisted as valid in the DNS of the SMTP envelope MAIL FROM address domain?

Check your domain on SPF:
```bash
dig -t TXT example.com
```

SPF technology is tied to the SMTP envelope MAIL FROM address which is specified with the `.from_addr` method and then stored into the Return-Path header by the receiving server, and it has nothing in common with the headers like From `.from_`, Reply-To `.reply_to`, or Sender `.header("Sender")`.

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

### DMARC
What is your policy concerning SPF and DKIM? What abuse address do you have?

Check your domain on DMARC:
```bash
dig -t TXT _dmarc.example.com
```
