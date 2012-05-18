# -*- coding: utf8 -*-
from distutils.core import setup, Extension
import sys
import commands

long_description = """
This is an small extension to the python kerberos package.
It adds support for "services for user to self/proxy" (s4u2s/s4u2p) kerberos functionality.
"""

setup (
    name = "s4u2p",
    version = "0.1",
    author="Norman Krämer",
    author_email="kraemer.norman@googlemail.com",
    description = "Kerberos high-level interface to the s4u kerberos functionality",
    long_description=long_description,
    classifiers = [
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 2",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: System :: Systems Administration :: Authentication/Directory"
        ],
    ext_modules = [
        Extension(
            "s4u2p",
            extra_link_args = commands.getoutput("krb5-config --libs gssapi").split(),
            extra_compile_args = commands.getoutput("krb5-config --cflags gssapi").split(),
            sources = [
                "src/s4u2p.c",
                "src/base64.c",
                "src/kerberosgss.c",
            ],
        ),
    ],
)
