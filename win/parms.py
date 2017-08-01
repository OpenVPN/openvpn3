PARMS = {
    "DEBUG" : False,
    "STATIC" : True,
    "OVPN3" : "c:\\src\\ovpn3",
    "TAP" : "c:\\src\\tap-windows6",
    "TAP_WIN_COMPONENT_ID" : "tap0901",  # Community: tap0901, Access Server: tapoas
    "DEP" : "z:\\james\\downloads",
    "BUILD" : "c:\\src\\ovpn3-build",
    "PATCH" : "c:\\src\\as\\pyovpn\\patch",
    "GIT" : "c:\\Program Files (x86)\\Git",
    "CPP_EXTRA" : "",
    "MSVC_DIR" : "c:\\Program Files (x86)\\Microsoft Visual Studio 14.0",
    "ARCH" : "amd64", # one of amd64, x86, or x86_xp (note that x86_xp requires vcvarsall.bat patch)
    "LIB_VERSIONS" : {
        'asio'     : "asio-20170227",
        'mbedtls'  : "mbedtls-2.4.0",
        'lz4'      : "lz4-1.7.5",
    }
}

try:
    from parms_local import PARMS as parms_local
    PARMS.update(parms_local)
except ImportError:
    pass
