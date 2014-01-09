import sys
sys.modules['ssl'] = None
sys.modules['_hashlib'] = None

import memdbg

from twisted.scripts.trial import run
run()
