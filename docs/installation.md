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

* If planning to sign/encrypt with GPG, make sure it is installed with `sudo apt install gpg` — see also the [Configure your GPG](https://cz-nic.github.io/envelope/related-affairs/#configure-your-gpg) tutorial.
* If planning to use S/MIME, you might need a few [build prerequisites](https://cryptography.io/en/latest/installation/) first, ex: `sudo apt install build-essential libssl-dev libffi-dev python3-dev cargo pkg-config`
* If planning to send e-mails, prepare SMTP credentials or follow the [Configure your SMTP](https://cz-nic.github.io/envelope/related-affairs/#configure-your-smtp) tutorial.
* If your e-mails are to be received outside your local domain, see the [DMARC](https://cz-nic.github.io/envelope/related-affairs/#dmarc) section.
* [python-magic](https://pypi.org/project/python-magic/) is used as a dependency. Due to a [well-known](https://github.com/ahupp/python-magic/blob/master/COMPAT.md) name clash with the [file-magic](https://pypi.org/project/file-magic/) package, feel free to run `pip uninstall python-magic && pip install file-magic` if you need the latter — envelope is fully compatible with both. Both rely on `libmagic` under the hood, which is probably already installed; if not, [install](https://github.com/ahupp/python-magic?tab=readme-ov-file#installation) it with `sudo apt install libmagic1`.

## Bash completion
1. Run: `apt install bash-completion jq`
2. Copy [envelope-autocompletion.bash](https://github.com/CZ-NIC/envelope/blob/main/extra/envelope-autocompletion.bash) to `/etc/bash_completion.d/`
3. Restart terminal
