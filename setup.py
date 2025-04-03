from setuptools import setup, find_packages

# Read requirements
with open('requirements.txt') as f:
    requirements = f.read().splitlines()

setup(
    name="CryptoIoT-Python",
    version="2.0.0",
    install_requires=requirements,
    entry_points={
        'console_scripts': [
            'ciot-client=ciot_client2:main',
        ],
    },
    python_requires='>=3.6',
    description="CIoT Python Cient",
    author="David Wischnjak",
    url="https://github.com/wladimir-computin/CryptoIoT-Python"
)
