import os, re

from utils import *

def compile_one_file(parms, srcfile, incdirs):
    extra = {
        "srcfile" : srcfile,
        "incdirs" : ' '.join([r"/I %s" % (x,) for x in incdirs]),
        }

    vc_parms(parms, extra)

    vc_cmd(parms, r"cl /c /DNOMINMAX /D_CRT_SECURE_NO_WARNINGS %(incdirs)s /EHsc %(link_static_dynamic_flags)s /W3 %(dbg_rel_flags)s /nologo %(srcfile)s" % extra, arch=os.environ.get("ARCH"))

def build_asio(parms):
    print "**************** ASIO"
    with Cd(build_dir(parms)) as cd:
        with ModEnv('PATH', "%s\\bin;%s" % (parms.get('GIT'), os.environ['PATH'])):
            dist = os.path.realpath('asio')
            rmtree(dist)
            d = expand('asio', parms['DEP'], parms.get('LIB_VERSIONS'))
            os.rename(d, dist)

def build_mbedtls(parms):
    print "**************** MBEDTLS"
    with Cd(build_dir(parms)) as cd:
        with ModEnv('PATH', "%s\\bin;%s" % (parms.get('GIT'), os.environ['PATH'])):
            dist = os.path.realpath('mbedtls')
            rmtree(dist)
            d = expand('mbedtls', parms['DEP'], parms.get('LIB_VERSIONS'))
            if d.endswith("-apache"):
                d = d[:-7]
            elif d.endswith("-gpl"):
                d = d[:-4]

            os.rename(d, dist)

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
    with Cd(build_dir(parms)) as cd:
        with ModEnv('PATH', "%s\\bin;%s" % (parms.get('GIT'), os.environ['PATH'])):
            dist = os.path.realpath('lz4')
            rmtree(dist)
            d = expand('lz4', parms['DEP'], parms.get('LIB_VERSIONS'))
            os.rename(d, dist)
            os.chdir(os.path.join(dist, "lib"))
            compile_one_file(parms, "lz4.c", ())
            vc_cmd(parms, r"lib /OUT:lz4.lib lz4.obj")

def build_jsoncpp(parms):
    if 'jsoncpp' in parms['LIB_VERSIONS']:
        print "**************** JSONCPP"
        with Cd(build_dir(parms)) as cd:
            with ModEnv('PATH', "%s\\bin;%s" % (parms.get('GIT'), os.environ['PATH'])):
                dist = os.path.realpath('jsoncpp')
                rmtree(dist)
                d = expand('jsoncpp', parms['DEP'], parms.get('LIB_VERSIONS'))
                os.rename(d, dist)
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

if __name__ == "__main__":
    from parms import PARMS
    build_all(PARMS)
