import os, re

from utils import *
from parms import PARMS

if len(sys.argv) >= 2:
    srcfile = sys.argv[1]
else:
    srcfile = os.path.join(PARMS['OVPN3'], "test", "ovpncli", "cli.cpp")

if PARMS['DEBUG']:
    dbg_rel_flags = "/Zi"
else:
    dbg_rel_flags = "/O2"

paths = {
    "ovpn3"   : PARMS['OVPN3'],
    "tap"     : os.path.join(PARMS['TAP'], 'src'),
    "tap_component_id" : PARMS['TAP_WIN_COMPONENT_ID'],
    "boost"   : os.path.join(PARMS['BUILD'], PARMS['LIB_VERSIONS']['boost']),
    "openssl" : os.path.join(PARMS['BUILD'], "openssl"),
    "srcfile" : srcfile,
    "dbg_rel_flags" : dbg_rel_flags,
}

# add to link dynamically: /DBOOST_ALL_DYN_LINK
# add to support pre-Vista: /D_WIN32_WINNT=0x0501
# add to support Vista and later: /D_WIN32_WINNT=0x0600

vc_cmd(PARMS, r"cl /D_WIN32_WINNT=0x0600 /DNOMINMAX /D_CRT_SECURE_NO_WARNINGS /DBOOST_ALL_DYN_LINK /DUSE_OPENSSL /I %(openssl)s\include /I %(boost)s /I %(tap)s -DTAP_WIN_COMPONENT_ID=%(tap_component_id)s /I %(ovpn3)s /GL /EHsc /MD /W3 %(dbg_rel_flags)s /nologo %(srcfile)s /link /LIBPATH:%(boost)s\stage\lib /LIBPATH:%(openssl)s\lib libeay32.lib ssleay32.lib ws2_32.lib crypt32.lib iphlpapi.lib winmm.lib user32.lib gdi32.lib advapi32.lib wininet.lib shell32.lib ole32.lib" % paths, arch=os.environ.get("ARCH"))
