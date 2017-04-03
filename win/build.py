#!/c/python27/python

import os

from utils import *

def cli_cpp(parms):
    return os.path.join(parms['OVPN3'], "core", "test", "ovpncli", "cli.cpp")

def src_fn(parms, srcfile):
    # Get source file name
    if srcfile:
        if '.' not in os.path.basename(srcfile):
            srcfile += ".cpp"
    else:
        srcfile = cli_cpp(parms)
    return srcfile

def src_fn_argv(parms, argv):
    srcfile = None
    if len(argv) >= 1:
        srcfile = argv[0]
    return src_fn(parms, srcfile)

def build(parms, srcfile):
    # Debug?
    if parms['DEBUG']:
        dbg_rel_flags = "/Zi"
    else:
        dbg_rel_flags = "/O2"

    # Dictionary we will use to substitute parameters
    # onto VC command line.
    options = {
        "ovpn3"   : parms['OVPN3'],
        "tap"     : os.path.join(parms['TAP'], 'src'),
        "tap_component_id" : parms['TAP_WIN_COMPONENT_ID'],
        "asio"    : os.path.join(build_dir(parms), "asio"),
        "mbedtls" : os.path.join(build_dir(parms), "mbedtls"),
        "lz4" : os.path.join(build_dir(parms), "lz4", "lib"),
        "srcfile" : srcfile,
        "extra_defs" : parms['CPP_EXTRA'],
        "extra_inc" : "",
        "extra_lib_path" : "",
        "extra_lib" : "",
    }

    vc_parms(parms, options)

    # Do we need to support XP and Win 2003?
    arch = os.environ.get("ARCH", parms['ARCH'])
    if arch == "x86_xp":
        options['extra_defs'] += " /D_WIN32_WINNT=0x0501"  # pre-Vista
    else:
        options['extra_defs'] += " /D_WIN32_WINNT=0x0600"  # Vista and later
        options['extra_lib'] += " fwpuclnt.lib"

    # Add jsoncpp (optional)
    if 'jsoncpp' in parms['LIB_VERSIONS']:
        options["jsoncpp"] = os.path.join(build_dir(parms), "jsoncpp")
        options['extra_inc'] += " /DHAVE_JSONCPP /I %(jsoncpp)s/dist" % options
        options['extra_lib_path'] += " /LIBPATH:%(jsoncpp)s/dist" % options
        options['extra_lib'] += " jsoncpp.lib"

    # Build OpenVPN Connect
    if parms.get("CONNECT"):
        options['extra_inc'] += " /I " + os.path.join(parms['OVPN3'], "common")

    # build it
    vc_cmd(parms, r"cl %(extra_defs)s /DNOMINMAX /D_CRT_SECURE_NO_WARNINGS /DUSE_ASIO /DASIO_STANDALONE /DASIO_NO_DEPRECATED /I %(asio)s\asio\include /DUSE_MBEDTLS /I %(mbedtls)s\include /DHAVE_LZ4 /I %(lz4)s%(extra_inc)s -DTAP_WIN_COMPONENT_ID=%(tap_component_id)s /I %(tap)s /I %(ovpn3)s\core /GL /EHsc %(link_static_dynamic_flags)s /W0 %(dbg_rel_flags)s /nologo %(srcfile)s /link /LIBPATH:%(mbedtls)s\library /LIBPATH:%(lz4)s%(extra_lib_path)s mbedtls.lib lz4.lib%(extra_lib)s ws2_32.lib crypt32.lib iphlpapi.lib winmm.lib user32.lib gdi32.lib advapi32.lib wininet.lib shell32.lib ole32.lib rpcrt4.lib" % options, arch=os.environ.get("ARCH"))

if __name__ == "__main__":
    import sys
    from parms import PARMS
    build(PARMS, src_fn_argv(PARMS, sys.argv[1:]))
