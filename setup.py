from setuptools import setup

with open("requirements.txt", "r") as f:
    requirements = f.read()

setup(
    name='gpggo',
    version='0.6',
    packages=['.'],
    author='Edvard Rejthar',
    author_email='edvard.rejthar@nic.cz',
    url='https://github.com/CZ-NIC/gpggo',
    license='GNU GPLv3',
    description='You insert a message and receive signed and/or encrypted output by a single line.',
    install_requires=[requirements.split("\n")],
    entry_points={
        'console_scripts': [
            'gpggo=gpggo:main',
        ],
    }#,
    #package_data={'convey': ['defaults/*']},
    #include_package_data=True
)
