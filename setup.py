#!/usr/bin/env python

from os import path
from setuptools import setup, find_packages

__folder__ = path.abspath(path.dirname(__file__))

with open(path.join(__folder__, "README.md")) as readme_file:
    long_description = readme_file.read()

about = {}
with open(path.join(__folder__, "kompose_ex", "__version__.py")) as about_file:
    exec(about_file.read(), about)

with open(path.join(__folder__, "requirements.txt")) as req_file:
    install_requires = req_file.readlines()

setup(
    name=about["__title__"],
    version=about["__version__"],
    description=about["__description__"],
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Tomer Zait (realgam3)",
    author_email="realgam3@gmail.com",
    packages=find_packages(exclude=["examples", "tests"]),
    py_modules=["kompose_ex"],
    entry_points={
        "console_scripts": [
            "kompose-ex = kompose_ex:main",
        ]
    },
    install_requires=install_requires,
    license="GPLv3",
    platforms="any",
    url=about["__url__"],
    classifiers=[
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: Science/Research",
        "Natural Language :: English",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
        "Topic :: Internet",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Internet :: Proxy Servers",
        "Topic :: Software Development :: Testing",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    extras_require={
        "route53": ["boto3 >= 1.24.27"],
        "eks": ["awscli >= 1.25.27"],
        "aws": ["boto3 >= 1.24.27", "awscli >= 1.25.27"],
    },
    project_urls={
        "Source": "https://gitlab.com/BSidesTLV/CTF22/kompose-ex",
    },
)
