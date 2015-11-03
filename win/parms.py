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
        'asio'     : "asio-20150924",
        'polarssl' : "polarssl-1.3.9a",
        'lz4'      : "lz4-r120",
        }
}
