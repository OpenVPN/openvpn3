OpenVPN 3
=========

OpenVPN 3 is a C++ class library that implements the functionality
of an OpenVPN client, and is protocol-compatible with the OpenVPN
2.x branch.

OpenVPN 3 includes a minimal client wrapper (``cli``) that links in with
the library and provides basic command line functionality.

NOTE: As of early 2016, OpenVPN 3 is primarily of interest to developers
because it does not yet replicate the full functionality of OpenVPN 2.x.
In particular, server functionality is not yet implemented.

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

1. Asio -- https://github.com/chriskohlhoff/asio
2. PolarSSL/mbedTLS (1.3.15 or higher) -- https://tls.mbed.org/
3. LZ4 -- https://github.com/Cyan4973/lz4

For dependencies that are typically cloned from github vs.
provided as a .tar.gz file, tools are provided to convert
the github to a .tar.gz file.  See "snapshot" scripts under
$O3/core/deps

Note that while OpenSSL is listed in lib-versions, it is
not required for Mac builds.

Build the dependencies::

    OSX_ONLY=1 $O3/core/scripts/mac/build-all

Now build the OpenVPN 3 client executable::

    cd $O3/core
    . vars/vars-osx64
    . vars/setpath
    cd test/ovpncli
    PSSL=1 LZ4=1 build cli

This will build the OpenVPN 3 client library with a small client
wrapper (``cli``).  It will also statically link in all external
dependencies (Asio, PolarSSL, and LZ4), so ``cli`` may be distributed
to other Macs and will run as a standalone executable.

These build scripts will create a **x86_x64** Mac OS X executable,
with a minimum deployment target of 10.8.x.  The Mac OS X tuntap driver is not
required, as OpenVPN 3 can use the integrated utun interface if
available.

To view the client wrapper options::

    ./cli -h

To connect::

    ./cli client.ovpn
