# Returns 0 if the test is parsed, 1 if not.

import os
import sys
sys.path.insert(0,'..')
import pydnstest.scenario

file=sys.argv[1]
if pydnstest.scenario.parse_file(os.path.realpath(file)):
    sys.exit(0)
else:
    sys.exit(1)
