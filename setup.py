from pathlib import Path

from setuptools import setup

# using the same libraries in requirements.txt because after many articles I didn't understand any good reason why I shouldn't

# stand-alone or PyPi install
install_requires = []
for lines in (Path(p).read_text().splitlines() for p in ("requirements.txt", "envelope.egg-info/requires.txt") if Path(p).exists()):
    key = install_requires
    for line in lines:
        if line.startswith("["):
            # extras_require are exported to requires.txt, however, these are hardcoded here because they are optional
            break
        key.append(line)
    break

# load long description
p = Path("README.md")
long_description = p.read_text() if p.exists() else ""

setup(
    name='envelope',
    version='2.0.1',
    packages=['envelope'],
    author='Edvard Rejthar',
    author_email='edvard.rejthar@nic.cz',
    url='https://github.com/CZ-NIC/envelope',
    license='GNU GPLv3',
    description='Insert a message and attachments and send e-mail / sign / encrypt contents by a single line.',
    long_description=long_description,
    long_description_content_type="text/markdown",
    install_requires=install_requires,
    extras_require={
        "smime": "M2Crypto"  # need to have: `sudo apt install swig`
    },
    entry_points={
        'console_scripts': [
            'envelope=envelope.__main__:main',
        ],
    },
    classifiers=[
        'Programming Language :: Python :: 3'
    ],
    python_requires='>=3.6',
)
