"""
This is a legacy file that no-one currently knows how to use.

Please run your tests using ``py.test tests`` or ``tox``.
"""

import sys
sys.modules['ssl'] = None
sys.modules['_hashlib'] = None

try:
    from . import memdbg  # noqa
except Exception as e:
    pass

from twisted.scripts.trial import run
run()
