from setuptools import setup

with open("requirements.txt", "r") as f:
    requirements = f.read()

setup(
    name='envelope',
    version='0.8.1',
    packages=['.'],
    author='Edvard Rejthar',
    author_email='edvard.rejthar@nic.cz',
    url='https://github.com/CZ-NIC/envelope',
    license='GNU GPLv3',
    description='Insert a message and attachments and send e-mail / sign / encrypt contents by a single line.',
    install_requires=[requirements.split("\n")],
    entry_points={
        'console_scripts': [
            'envelope=envelope:main',
        ],
    }#,
    #package_data={'convey': ['defaults/*']},
    #include_package_data=True
)
