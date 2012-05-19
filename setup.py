# -*- coding: utf8 -*-
from distutils.core import setup, Extension
import commands

long_description = """
This is an small extension to the python kerberos package.
It adds support for "services for user to self/proxy" (s4u2s/s4u2p) kerberos functionality.
It adds authGSSImpersonation* functions that let you (as a server) act on behalf of a user.
No actual delegated ticket from a user needs to be forwarded to the server component.
Instead the server account needs to be set up as described here:
http://k5wiki.kerberos.org/wiki/Manual_Testing#Services4User_testing

For some overview of s4u see this:
http://msdn.microsoft.com/en-us/magazine/cc188757.aspx#S2

"""

setup (
    name = "s4u2p",
    version = "0.2",
    author="Norman Krämer",
    author_email="kraemer.norman@googlemail.com",
    description = "Kerberos high-level interface to the s4u kerberos functionality",
    long_description=long_description,
    url="https://github.com/may-day/s4u2p",
    download_url = "https://github.com/may-day/s4u2p/tarball/0.2",
    classifiers = [
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 2",
        "Development Status :: 3 - Alpha",
        "Environment :: Web Environment",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: System :: Systems Administration :: Authentication/Directory"
        ],
    license = "Apache License, Version 2.0",
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
