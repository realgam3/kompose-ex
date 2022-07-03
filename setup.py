#!/usr/bin/env python

from os import path
from setuptools import setup, find_packages

__folder__ = path.dirname(__file__)

with open(path.join(__folder__, "README.md")) as ld_file:
    long_description = ld_file.read()
    ld_file.flush()

with open(path.join(__folder__, "requirements.txt")) as req_file:
    install_requires = req_file.read()

setup(
    name="kompose-ex",
    version="1.0.0",
    description="kompose extended - extension of kompose for CTF ci/cd",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="RealGame (Tomer Zait)",
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
    url="https://gitlab.com/BSidesTLV/CTF22/kompose-ex",
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
        "Topic :: Software Development :: Libraries :: Python Modules"
    ]
)
