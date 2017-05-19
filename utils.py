#
# utils.py
#
#
import base64
import contextlib
import functools
import logging
import random
import string
import sys
import time
import threading

try:
    from urllib.parse import urljoin
except ImportError:
    from urlparse import urljoin

try:
    from urllib.parse import urlencode
except ImportError:
    from urllib import urlencode



#
# helpers
#
def setdict(d, k, v, should=lambda d,k,v: v is not None):
    if should(d, k, v):
        d[k] = v


def first(iterable, default=None, cond=None):
    """
    Find first matching item

    >>> first([1, 2, 3])
    1
    >>> first([1, 2, 3], cond=lambda x: x == 4)
    """
    if callable(cond):
        iterable = ( i for i in iterable if cond(i) )
    else:
        iterable = iter(iterable)
    try:
        return next(iterable)
    except StopIteration:
        return default


def buildurl(base, *args, **kwargs):
    """
    How to build a url

    >>> buildurl("http://myhost", "hello", "there", something=12)
    'http://myhost/hello/there?something=12'
    """
    if args and not base.endswith('/'):
        base = base + '/'
    argstr = "/".join(str(a) for a in args if a is not None)
    # filter our leading '/'
    if argstr.startswith('/'):
        argstr = argstr[1:]
    endpoint = urljoin(base, argstr)
    qargs = []
    for k,v in kwargs.items():
        if isinstance(v, (tuple, list)):
            items = ( (k,_v) for _v in v )
        else:
            items = ( (k,v), )
        # strip end '_'
        for k,v in items:
            if k.endswith('_'):
                k = k[:-1]
            qargs.append((k, v))
    query = urlencode(qargs)
    if query:
        endpoint = endpoint + "?" + query
    return endpoint

def is_online():
    from urllib.request import urlopen
    try:
        urlopen('http://216.58.192.142', timeout=1)
        return True
    except Exception:
        return False


def random_string(size):
    return ''.join([random.choice(string.ascii_letters + string.digits) for n in range(size)])


def encrypt(key, plaintext):
    """
    Symmetric encryption/decryption

    >>> ciphered = encrypt("mykey", "text")
    >>> decrypt("mykey", ciphered)
    'text'
    """
    from Crypto.Cipher import Blowfish
    from Crypto import Random
    from struct import pack

    if isinstance(key, str):
        key = key.encode()
    if isinstance(plaintext, str):
        plaintext = plaintext.encode()

    bs = Blowfish.block_size
    plen = bs - len(plaintext) % bs
    padding = [plen] * plen
    padding = pack('b'*plen, *padding)

    iv = Random.new().read(bs)
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    ciphertext = iv + cipher.encrypt(plaintext + padding)
    return base64.b64encode(ciphertext).decode()

def decrypt(key, ciphertext):
    from Crypto.Cipher import Blowfish
    from struct import pack

    if isinstance(key, str):
        key = key.encode()
    if isinstance(ciphertext, str):
        ciphertext = ciphertext.encode()
    ciphertext = base64.b64decode(ciphertext)

    bs = Blowfish.block_size
    iv = ciphertext[:bs]
    ciphertext = ciphertext[bs:]

    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    msg = cipher.decrypt(ciphertext)

    last_byte = msg[-1]
    idx = last_byte if isinstance(last_byte, int) else ord(last_byte)
    msg = msg[:-idx]
    return msg.decode()


_elapsed_local = threading.local()

@contextlib.contextmanager
def elapsed(msg="", logger=logging.debug):
    """
    Elapsed time context
    >>> with elapsed("hello", logger=print):
    ...     for i in range(1000): pass
    hello: ...us
    """
    then = time.time()
    indent = getattr(_elapsed_local, 'indent', 0)
    _elapsed_local.indent = indent + 1
    yield
    _elapsed_local.indent -= 1
    elapsed = time.time() - then
    if elapsed < 0.0001:
        estr = "%.3fus" % (elapsed * 1000000)
    elif elapsed < 0.1:
        estr = "%.3fms" % (elapsed * 1000)
    else:
        estr = "%.3fs" % elapsed
    if msg:
        msg = msg + ": "
    logger("  "*indent + msg + estr)


#
# Factory decorator
#
class Factory(object):
    """
    Factory decorator
    >>> factory = Factory()
    >>> @factory("foo")
    ... def func1(msg):
    ...     return "hello, %s" % msg
    >>> @factory("bar")
    ... @factory("baz")
    ... def func2():
    ...     return "bye"
    >>> factory.call('foo', 'there')
    'hello, there'
    >>> factory['bar']  # doctest: +ELLIPSIS
    <function func2 at ...>
    >>> factory['baz']  # doctest: +ELLIPSIS
    <function func2 at ...>
    """
    def __init__(self):
        self._mapped = {}

    def __contains__(self, key):
        return key in self._mapped

    def __getitem__(self, key):
        return self._mapped[key]

    def get(self, key, default=None):
        return self._mapped.get(key, default)

    # decorator
    def __call__(self, *keys):
        def _fn(fn):
            self._mapped.update( (k,fn) for k in keys )
            return fn
        return _fn

    # execution
    def call(self, key, *args, **kwargs):
        return self._mapped[key](*args, **kwargs)
