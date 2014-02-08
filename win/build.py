import os, re

from utils import *
from parms import PARMS

if len(sys.argv) >= 2:
    srcfile = sys.argv[1]
else:
    srcfile = os.path.join(PARMS['OVPN3'], "test", "ovpncli", "cli.cpp")

paths = {
    "openssl" : os.path.join(PARMS['BUILD'], "openssl"),
    "boost"   : os.path.join(PARMS['BUILD'], PARMS['LIB_VERSIONS']['boost']),
    "ovpn3"   : PARMS['OVPN3'],
    "srcfile" : srcfile,
}

# add to link dynamically: /DBOOST_ALL_DYN_LINK 

vc_cmd(PARMS, r"cl /D_WIN32_WINNT=0x0501 /DNOMINMAX /D_CRT_SECURE_NO_WARNINGS /DBOOST_ALL_DYN_LINK /DUSE_OPENSSL /I %(openssl)s\include /I %(boost)s /I %(ovpn3)s /GL /EHsc /O2 /MD /W3 /nologo %(srcfile)s /link /LIBPATH:%(boost)s\stage\lib /LIBPATH:%(openssl)s\lib libeay32.lib ssleay32.lib" % paths, arch=os.environ.get("ARCH"))
