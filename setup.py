from pathlib import Path

from setuptools import setup

# using the same libraries in requirements.txt because after many articles I didn't understand any good reason why I shouldn't
requirements = ""
p = Path("requirements.txt")
if p.exists():  # stand-alone install
    requirements = p.read_text()
else:  # PyPi install
    p = Path("envelope.egg-info/requires.txt")
    if p.exists():
        requirements = p.read_text()

# load long description
p = Path("README.md")
if p.exists():
    long_description = p.read_text()

setup(
    name='envelope',
    version='0.9.2',
    packages=['envelope'],
    author='Edvard Rejthar',
    author_email='edvard.rejthar@nic.cz',
    url='https://github.com/CZ-NIC/envelope',
    license='GNU GPLv3',
    description='Insert a message and attachments and send e-mail / sign / encrypt contents by a single line.',
    long_description=long_description,
    long_description_content_type="text/markdown",
    install_requires=[requirements.split("\n")],
    entry_points={
        'console_scripts': [
            'envelope=envelope:_cli',
        ],
    },
    classifiers=[
        'Programming Language :: Python :: 3'
    ],
    python_requires='>=3.6',
)
