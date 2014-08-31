OpenVPN 3
=========

OpenVPN 3 is a C++ class library that implements the functionality
of an OpenVPN client, and is protocol-compatible with the OpenVPN
2.x branch.

OpenVPN 3 includes a minimal client wrapper (``cli``) that links in with
the library and provides basic command line functionality.

NOTE: As of 2014, OpenVPN 3 is primarily of interest to developers
because it does not yet replicate the full functionality of OpenVPN 2.

Building OpenVPN 3 client on Mac OS X
-------------------------------------

OpenVPN 3 should be built in a non-root Mac OS X account.
Make sure that Xcode is installed with optional command-line tools.
(These instructions have been tested with Xcode 5.1.1).

Create the directories ``~/src`` and ``~/src/mac``::

    mkdir -p ~/src/mac

Clone the OpenVPN 3 repo::

    cd ~/src
    mkdir ovpn3
    cd ovpn3
    git clone ... core

Export the shell variable ``O3`` to point to the OpenVPN 3 top level
directory::

    export O3=~/src/ovpn3

Download source tarballs (``.tar.gz`` or ``.tgz``) for these dependency
libraries into ``~/Downloads``

See the file ``$O3/core/deps/lib-versions`` for the expected
version numbers of each dependency.  If you want to use a different
version of the library than listed here, you can edit this file.

1. Boost -- http://www.boost.org/
2. PolarSSL (1.3.4 or higher) -- https://polarssl.org/
3. Snappy -- https://code.google.com/p/snappy/
4. LZ4 -- https://code.google.com/p/lz4/

Note that while LZO and OpenSSL are listed in lib-versions, they are
not required for Mac builds.

Build the dependencies::

    OSX_ONLY=1 $O3/core/scripts/mac/build-all

Now build the OpenVPN 3 client executable::

    cd $O3/core
    . vars/vars-osx
    . vars/setpath
    cd test/ovpncli
    STRIP=1 PSSL=1 SNAP=1 LZ4=1 build cli

This will build the OpenVPN 3 client library with a small client
wrapper (``cli``).  It will also statically link in all external
dependencies (Boost, PolarSSL,
LZ4, and Snappy), so ``cli`` may be distributed to other Macs and
will run as a standalone executable.

These build scripts will create a "fat" Mac OS X executable with
support for both **x86_x64** and **i386** architectures, with a minimum
deployment target of 10.6.x.  The Mac OS X tuntap driver is not
required, as OpenVPN 3 can use the integrated utun interface if
available.

To view the client wrapper options::

    ./cli -h

To connect::

    ./cli client.ovpn
