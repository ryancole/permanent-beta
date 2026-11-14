"""IDA loader for the Permanent Beta plugin. Copy this file and the `permanent_beta` folder into IDA's plugins
directory (see README.md)."""

import os
import sys

_here = os.path.dirname(os.path.abspath(__file__))
if _here not in sys.path:
    sys.path.insert(0, _here)

from permanent_beta.plugin import PermanentBetaPlugin  # noqa: E402


def PLUGIN_ENTRY():
    return PermanentBetaPlugin()
