import sys
sys.modules['ssl'] = None
sys.modules['_hashlib'] = None

try:
    from OpenSSL.test import memdbg  # noqa
except Exception as e:
    pass

from twisted.scripts.trial import run
run()
