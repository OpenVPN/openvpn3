import os, re

from utils import *
from parms import PARMS

if len(sys.argv) >= 2:
    srcfile = sys.argv[1]
else:
    srcfile = os.path.join(PARMS['OVPN3'], "core", "test", "ovpncli", "cli.cpp")

if PARMS['DEBUG']:
    dbg_rel_flags = "/Zi"
else:
    dbg_rel_flags = "/O2"

paths = {
    "ovpn3"   : PARMS['OVPN3'],
    "tap"     : os.path.join(PARMS['TAP'], 'src'),
    "tap_component_id" : PARMS['TAP_WIN_COMPONENT_ID'],
    "asio"    : os.path.join(PARMS['BUILD'], "asio"),
    "polarssl" : os.path.join(PARMS['BUILD'], "polarssl"),
    "lz4" : os.path.join(PARMS['BUILD'], "lz4"),
    "jsoncpp" : os.path.join(PARMS['BUILD'], "jsoncpp"), # optional
    "srcfile" : srcfile,
    "dbg_rel_flags" : dbg_rel_flags,
}

# add to support pre-Vista: /D_WIN32_WINNT=0x0501
# add to support Vista and later: /D_WIN32_WINNT=0x0600

paths['extra_inc'] = ""
paths['extra_lib_path'] = ""
paths['extra_lib'] = ""

if 'jsoncpp' in paths:
    paths['extra_inc'] += " /DHAVE_JSONCPP /I %(jsoncpp)s/dist" % paths
    paths['extra_lib_path'] += " /LIBPATH:%(jsoncpp)s/dist" % paths
    paths['extra_lib'] += " jsoncpp.lib"

vc_cmd(PARMS, r"cl /D_WIN32_WINNT=0x0600 /DNOMINMAX /D_CRT_SECURE_NO_WARNINGS /DASIO_STANDALONE /DASIO_NO_DEPRECATED /I %(asio)s\asio\include /DUSE_POLARSSL /I %(polarssl)s\include /DHAVE_LZ4 /I %(lz4)s%(extra_inc)s -DPRIVATE_TUNNEL_PROXY /I %(ovpn3)s\common -DTAP_WIN_COMPONENT_ID=%(tap_component_id)s /I %(tap)s /I %(ovpn3)s\core /GL /EHsc /MD /W0 %(dbg_rel_flags)s /nologo %(srcfile)s /link /LIBPATH:%(polarssl)s\library /LIBPATH:%(lz4)s%(extra_lib_path)s polarssl.lib lz4.lib%(extra_lib)s ws2_32.lib crypt32.lib iphlpapi.lib winmm.lib user32.lib gdi32.lib advapi32.lib wininet.lib shell32.lib ole32.lib" % paths, arch=os.environ.get("ARCH"))
