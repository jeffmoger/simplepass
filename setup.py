from setuptools import setup, find_packages

with open("README.md", "r") as fh:
    long_description = fh.read()

requirements = ["pyperclip", "passlib", "cryptography"]

setup(
    name="SimplePass",
    version="1.0.2",
    author="Example Author",
    author_email="jeff@moger.com",
    description="A simple password manager for the command line.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="",
    packages=find_packages(),
    install_requires=requirements,
    classifiers=[
        "Programming Language :: Python :: 3.7",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
    ],
    entry_points={
        'console_scripts': [
            'spass = spass:main',
        ],
    }
)
