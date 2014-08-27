import os, sys, re, shutil, tarfile, subprocess

j = os.path.join

class Cd(object):
    """
    Cd is a context manager that allows
    you to temporary change the working directory.

    with Cd(dir) as cd:
        ...
    """

    def __init__(self, directory):
        self._dir = directory

    def orig(self):
        return self._orig

    def __enter__(self):
        self._orig = os.getcwd()
        os.chdir(self._dir)
        return self

    def __exit__(self, *args):
        os.chdir(self._orig)

class ModEnv(object):
    """
    Context manager for temporarily
    modifying an env var.  Normally used to make
    changes to PATH.
    """

    def __init__(self, key, value):
        self.key = key;
        self.value = value;

    def __enter__(self):
        self.orig_value = os.environ.get(self.key)
        os.environ[self.key] = self.value
        return self

    def __exit__(self, *args):
        if self.orig_value is not None:
            os.environ[self.key] = self.orig_value            

def rmtree(dir):
    print "RMTREE", dir
    shutil.rmtree(dir, ignore_errors=True)

def makedirs(dir):
    print "MAKEDIRS", dir
    os.makedirs(dir)

def cp(src, dest):
    print "COPY %s %s" % (src, dest)
    shutil.copy2(src, dest)

def wipetree(dir):
    print "WIPETREE", dir
    shutil.rmtree(dir, ignore_errors=True)
    if not os.path.isdir(dir):
        os.mkdir(dir)

def extract_dict(d, k, default=None):
    if k in d:
        v = d[k]
        del d[k]
    else:
        v = default
    return v

def scan_prefixes(prefix, dir, filt=None):
    fns = []
    for dirpath, dirnames, filenames in os.walk(dir):
        for f in filenames:
            if f.startswith(prefix) and (filt is None or filt(f)):
                fns.append(f)
        break
    return fns

def one_prefix(prefix, dir, filt=None):
    f = scan_prefixes(prefix, dir, filt)
    if len(f) == 0:
        raise ValueError("prefix %r not found in dir %r" % (prefix, dir))
    elif len(f) >= 2:
        raise ValueError("prefix %r is ambiguous in dir %r: %r" % (prefix, dir, f))
    return f[0]

def tarsplit(fn):
    if fn.endswith(".tar.gz"):
        t = 'gz'
        b = fn[:-7]
    elif fn.endswith(".tgz"):
        t = 'gz'
        b = fn[:-4]
    elif fn.endswith(".tar.bz2"):
        t = 'bz2'
        b = fn[:-8]
    elif fn.endswith(".tbz"):
        t = 'bz2'
        b = fn[:-4]
    elif fn.endswith(".tar.xz"):
        t = 'xz'
        b = fn[:-7]
    else:
        raise ValueError("unrecognized tar file type: %r" % (fn,))
    return b, t

def tarsplit_filt(fn):
    try:
        tarsplit(fn)
    except:
        return False
    else:
        return True

def tarextract(fn, t):
    print "TAR EXTRACT %s [%s]" % (fn, t)
    tar = tarfile.open(fn, mode='r:'+t)
    try:
        tar.extractall()
    finally:
        tar.close()

def expand(pkg_prefix, srcdir, lib_versions=None, noop=False):
    if lib_versions and pkg_prefix in lib_versions:
        f = one_prefix(lib_versions[pkg_prefix], srcdir, tarsplit_filt)
    else:
        f = one_prefix(pkg_prefix, srcdir, tarsplit_filt)
    b, t = tarsplit(f)

    if not noop:
        # remove previous directory
        rmtree(b)

        # expand it
        tarextract(os.path.join(srcdir, f), t)

    return b

def call(cmd, **kw):
    print "***", cmd

    ignore_errors = extract_dict(kw, 'ignore_errors', False)
    extra_env = extract_dict(kw, 'extra_env', None)
    if extra_env:
        env = kw.get('env', os.environ).copy()
        env.update(extra_env)
        kw['env'] = env
    succeed = extract_dict(kw, 'succeed', 0)

    # show environment
    se = kw.get('env')
    if se:
        show_env(se)
        print "***"

    ret = subprocess.call(cmd, **kw)
    if not ignore_errors and ret != succeed:
        raise ValueError("command failed with status %r (expected %r)" % (ret, succeed))

def vc_cmd(parms, cmd, arch=None, succeed=0):
    # arch should be one of amd64 (alias x64), x86, or None
    # (if None, use parms.py value)
    if arch is None:
        arch = parms['ARCH']
    if arch == "x64":
        arch = "amd64"
    with ModEnv('PATH', "%s;%s\\VC" % (os.environ['PATH'], parms['MSVC_DIR'])):
        status = call('vcvarsall.bat %s && %s' % (arch, cmd), shell=True, succeed=succeed)

def patchfile(pkg_prefix, patchdir):
    return os.path.join(patchdir, one_prefix(pkg_prefix, patchdir))

def patch(pkg_prefix, patchdir):
    patch_fn = patchfile(pkg_prefix, patchdir)
    print "PATCH", patch_fn
    call(['patch', '-p1', '-i', patch_fn])
