# Installation
* Install with a single command from [PyPi](https://pypi.org/project/envelope/)
    ```bash
    pip3 install envelope
    ```

    * Or install current GitHub master
    ```bash
    pip3 install git+https://github.com/CZ-NIC/envelope.git
    ```
    * Or just download the project and launch `python3 -m envelope`
* If planning to sign/encrypt with GPG, assure you have it on the system with `sudo apt install gpg` and possibly see [Configure your GPG](https://cz-nic.github.io/envelope/related-affairs/#configure-your-gpg) tutorial.
* If planning to use S/MIME, you might be required to ensure some [prerequisites](https://cryptography.io/en/latest/installation/), ex: `sudo apt install build-essential libssl-dev libffi-dev python3-dev cargo pkg-config`
* If planning to send e-mails, prepare SMTP credentials or visit [Configure your SMTP](https://cz-nic.github.io/envelope/related-affairs/#configure-your-smtp) tutorial.
* If your e-mails are to be received outside your local domain, visit [DMARC](https://cz-nic.github.io/envelope/related-affairs/#dmarc) section.
* Package [python-magic](https://pypi.org/project/python-magic/) is used as a dependency. Due to a [well-known](https://github.com/ahupp/python-magic/blob/master/COMPAT.md) name clash with the [file-magic](https://pypi.org/project/file-magic/) package, in case you need to use the latter, don't worry to run `pip uninstall python-magic && pip install file-magic` after installing envelope which is fully compatible with both projects. Both use `libmagic` under the hood which is probably already installed. However, if it is not, [install](https://github.com/ahupp/python-magic?tab=readme-ov-file#installation) `sudo apt install libmagic1`.

## Bash completion
1. Run: `apt install bash-completion jq`
2. Copy: [https://github.com/CZ-NIC/envelope/blob/main/extra/envelope-autocompletion.bash](https://github.com/CZ-NIC/envelope/blob/main/extra/envelope-autocompletion.bash) to `/etc/bash_completion.d/`
3. Restart terminal
