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

def scan_prefixes(prefix, dir):
    fns = []
    for dirpath, dirnames, filenames in os.walk(dir):
        for f in filenames:
            if f.startswith(prefix):
                fns.append(f)
        break
    return fns

def one_prefix(prefix, dir):
    f = scan_prefixes(prefix, dir)
    if len(f) == 0:
        raise ValueError("prefix %r not found in dir %r" % (prefix, dir))
    elif len(f) >= 2:
        raise ValueError("prefix %r is ambiguous in dir %r: %r" % (prefix, dir, f))
    return f[0]

def tarsplit(fn):
    if fn.endswith(".tar.gz") or fn.endswith(".tgz"):
        t = 'gz'
        b = fn[:-7]
    elif fn.endswith(".tar.bz2") or fn.endswith(".tbz"):
        t = 'bz2'
        b = fn[:-8]
    else:
        raise ValueError("unrecognized tar file type: %r" % (fn,))
    return b, t

def tarextract(fn, t):
    print "TAR EXTRACT %s [%s]" % (fn, t)
    tar = tarfile.open(fn, mode='r:'+t)
    try:
        tar.extractall()
    finally:
        tar.close()

def expand(pkg_prefix, srcdir):
    f = one_prefix(pkg_prefix, srcdir)
    b, t = tarsplit(f)

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

    ret = subprocess.call(cmd, **kw)
    if not ignore_errors and ret != succeed:
        raise ValueError("command failed with status %r (expected %r)" % (ret, succeed))

def vc_cmd(parms, cmd, succeed=0):
    with ModEnv('PATH', "%s;%s\\VC" % (os.environ['PATH'], parms['MSVC_DIR'])):
        status = call('vcvarsall.bat x86 && %s' % (cmd,), shell=True, succeed=succeed)
