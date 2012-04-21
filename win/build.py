import os, re

from utils import *
from parms import *

paths = {
    "openssl" : r"C:\src\ovpn3-build\openssl",
    "boost"   : r"C:\src\ovpn3-build\boost_1_48_0",
    "ovpn3"   : r"C:\src\ovpn3",
    "target"  : sys.argv[1],
}

# add to link dynamically: /DBOOST_ALL_DYN_LINK 

vc_cmd(parms, r"cl /D_WIN32_WINNT=0x0501 /DNOMINMAX /D_CRT_SECURE_NO_WARNINGS /DUSE_OPENSSL /I %(openssl)s\include /I %(boost)s /I %(ovpn3)s /GL /EHsc /O2 /MD /W3 /nologo %(target)s.cpp /link /LIBPATH:%(boost)s\stage\lib /LIBPATH:%(openssl)s\lib libeay32.lib ssleay32.lib" % paths)
