=========================================================
s4u2p Package

Copyright (c) 2012 Norman Krämer. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

=========================================================

This Python package is a high-level wrapper for the impersonation Kerberos (GSSAPI) operations.

Most of the code is based on the kerberos 1.1.1 python package
and from http://k5wiki.kerberos.org/wiki/Projects/Services4User.

========
CONTENTS
========

    src/               : directory in which C source code resides.
    setup.py           : Python distutils extension build script.
    README.txt         : what you are reading
    s4u2p.py        : Python api documentation/stub implementation.

=====
BUILD
=====

In this directory, run:

    python setup.py build

=======
TESTING
=======

For a setup read this:

http://k5wiki.kerberos.org/wiki/Manual_Testing#Services4User_testing  (*)

(n.b.: i had to include the REALM in the upn of the computer account)

To test the whole thing i created a simple website "username" which when called simply replies with a Hello <authenticated user>.
It is deployed on an IIS 7.5 webserver with windows authentication enabled as the only authentication method.

So i have the following parts:

The website i visit as an impersonated user: http://webserver/username/
A service principalname, which is created with IIS installation (otherwise use setspn.exe): http@webserver  (or http/webserver.fqdn)
The server keytab file which contains the keys of the computeraccount as created in (*): server.keytab
The upn of the computeraccount: host/server.fqdn
The (kerberos) user i want to impersonate: otheruser

With that i do:

1) kinit -kt ./server.keytab host/server.fqdn
2) PYTHONPATH=build/lib.xxx python test.py --user otheruser --host webserver --servicename HTTP@webserver --path /username/ --keytab ./server.keytab

===========
Python APIs
===========

See s4u2p.py.
