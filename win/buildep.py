import os, re

from utils import *
from lib_versions import *

def compile_one_file(parms, srcfile, incdirs):
    extra = {
        "srcfile" : srcfile,
        "incdirs" : ' '.join([r"/I %s" % (x,) for x in incdirs]),
        }

    vc_parms(parms, extra)

    vc_cmd(parms, r"cl /c /DNOMINMAX /D_CRT_SECURE_NO_WARNINGS %(incdirs)s /EHsc %(link_static_dynamic_flags)s /W3 %(dbg_rel_flags)s /nologo %(srcfile)s" % extra, arch=os.environ.get("ARCH"))

def build_asio(parms):
    print "**************** ASIO"
    with Cd(build_dir(parms)):
        url = "https://github.com/chriskohlhoff/asio/archive/%s.tar.gz" % ASIO_VERSION
        arch_path = os.path.join(build_dir(parms), download(url))
        with ModEnv('PATH', "%s\\bin;%s" % (parms.get('GIT'), os.environ['PATH'])):
            extract(arch_path, "gz")
            rmtree("asio")
            os.rename("asio-%s" % ASIO_VERSION, "asio")
            rm(arch_path)

def build_mbedtls(parms):
    print "**************** MBEDTLS"
    with Cd(build_dir(parms)):
        url = "https://tls.mbed.org/download/mbedtls-%s-apache.tgz" % MBEDTLS_VERSION
        arch_path = os.path.join(build_dir(parms), download(url))
        with ModEnv('PATH', "%s\\bin;%s" % (parms.get('GIT'), os.environ['PATH'])):
            extract(arch_path, "gz")
            dist = os.path.realpath('mbedtls')
            rmtree(dist)
            os.rename("mbedtls-%s" % MBEDTLS_VERSION, dist)
            rm(arch_path)

            # edit mbedTLS config.h
            conf_fn = os.path.join(dist, 'include', 'mbedtls', 'config.h')
            with open(conf_fn) as f:
                conf = f.read()
            conf = re.sub(r"^//(?=#define MBEDTLS_MD4_C)", "", conf, flags=re.M);
            with open(conf_fn, 'w') as f:
                f.write(conf)

            # compile the source files
            os.chdir(os.path.join(dist, "library"))
            obj = []
            for dirpath, dirnames, filenames in os.walk("."):
                for f in filenames:
                    if f.endswith(".c"):
                        compile_one_file(parms, f, (r"..\include",))
                        obj.append(f[:-2]+".obj")
                break

            # collect object files into mbedtls.lib
            vc_cmd(parms, r"lib /OUT:mbedtls.lib " + ' '.join(obj))

def build_lz4(parms):
    print "**************** LZ4"
    with Cd(build_dir(parms)):
        url = "https://github.com/lz4/lz4/archive/v%s.tar.gz" % LZ4_VERSION
        arch_name = download(url)
        with ModEnv('PATH', "%s\\bin;%s" % (parms.get('GIT'), os.environ['PATH'])):
            extract(arch_name, "gz")
            dist = os.path.realpath('lz4')
            rmtree(dist)
            os.rename("lz4-%s" % LZ4_VERSION, dist)
            rm(arch_name)
            os.chdir(os.path.join(dist, "lib"))
            compile_one_file(parms, "lz4.c", ())
            vc_cmd(parms, r"lib /OUT:lz4.lib lz4.obj")

def build_tap(parms):
    print "**************** Windows-TAP"
    with Cd(build_dir(parms)):
        url = "https://github.com/OpenVPN/tap-windows6/archive/%s.zip" % TAP_VERSION
        arch_name = download(url)
        with ModEnv('PATH', "%s\\bin;%s" % (parms.get('GIT'), os.environ['PATH'])):
            extract(arch_name, "zip")
            dist = os.path.realpath('tap-windows')
            rmtree(dist)
            os.rename("tap-windows6-%s" % TAP_VERSION, dist)
            rm(arch_name)

def build_jsoncpp(parms):
    print "**************** JSONCPP"
    with Cd(build_dir(parms)):
        url = "https://github.com/open-source-parsers/jsoncpp/archive/%s.tar.gz" % JSONCPP_VERSION
        arch_name = download(url)
        with ModEnv('PATH', "%s\\bin;%s" % (parms.get('GIT'), os.environ['PATH'])):
            dist = os.path.realpath('jsoncpp')
            rmtree(dist)
            extract(arch_name, "gz")
            rm(arch_name)
            os.rename("jsoncpp-%s" % JSONCPP_VERSION, dist)
            os.chdir(dist)
            call(["python", "amalgamate.py"])
            os.chdir(os.path.join(dist, "dist"))
            compile_one_file(parms, "jsoncpp.cpp", (".",))
            vc_cmd(parms, r"lib /OUT:jsoncpp.lib jsoncpp.obj")

def build_all(parms):
    wipetree(build_dir(parms))
    build_asio(parms)
    build_mbedtls(parms)
    build_lz4(parms)
    build_jsoncpp(parms)
    build_tap(parms)

if __name__ == "__main__":
    build_all(read_params())
