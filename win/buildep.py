import os, re

from utils import *
from parms import *

patch_mk1mf_match = r"""
(.*)
([ \t]*chop\;[ \t]*[\r\n]+
[ \t]*\(\$key\,\$val\)\=\/\^\(\[\^\=\]\+\)\=\(\.\*\)\/\;[ \t]*[\r\n]+)
([ \t]*if \(\$key eq \"RELATIVE_DIRECTORY\"\)[ \t]*[\r\n]+
[ \t]*\{[ \t]*[\r\n]+
[ \t]*if \(\$lib ne \"\"\)[ \t]*[\r\n]+)
(.*)
"""

patch_mk1mf_add = """\

	# On some Windows machines, $val has linefeeds at the end, which confuses
	# subsequent code in this file. So we strip all whitespace at the end.
	$val =~ s/\s+$//;

"""

def build_openssl(parms):
    def patch_mk1mf():
        r = re.compile(patch_mk1mf_match.replace('\n', ''), re.DOTALL)
        fn = "util/mk1mf.pl"
        with open(fn) as f:
            content = f.read()
        m = re.match(r, content)
        if m:
            print "PATCHING", fn
            g = m.groups()
            with open(fn, "w") as f:
                f.write(g[0] + g[1] + patch_mk1mf_add + g[2] + g[3])
        else:
            raise ValueError("error patching " + fn)

    print "**************** OpenSSL"
    with Cd(parms['BUILD']) as cd:
        dist = os.path.realpath('openssl')
        rmtree(dist)
        d = expand('openssl', parms['DEP'])
        os.chdir(d)
        patch_mk1mf()
        makedirs(dist)
        call(['perl', 'Configure', 'VC-WIN32', 'no-idea', 'no-mdc2', 'no-rc5', '--prefix=%s' % (dist,)])
        vc_cmd(parms, "ms\\do_nasm") # was: "ms\\do_masm"
        vc_cmd(parms, "nmake -f ms\\ntdll.mak")
        vc_cmd(parms, "nmake -f ms\\ntdll.mak install")

def build_boost(parms):
    print "**************** Boost"
    with Cd(parms['BUILD']) as cd:
        d = expand('boost', parms['DEP'])
        os.chdir(d)
        call("bootstrap", shell=True)
        call("b2 --toolset=msvc-10.0 --build-type=complete stage", shell=True)
        #call("b2 --toolset=msvc-10.0 variant=release link=shared threading=multi runtime-link=shared stage", shell=True)

wipetree(parms['BUILD'])
build_openssl(parms)
build_boost(parms)
