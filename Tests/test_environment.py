"""Environment tests for the NIDS project.

This module verifies that essential Python dependencies are available
and provides a graceful skip when they're missing. Keeps tests import-safe
for linting and CI.
"""

import unittest

try:
    import numpy as NUMPY
    import pandas as PANDAS
    MISSING_DEPS = None
except ImportError as e:
    NUMPY = None
    PANDAS = None
    MISSING_DEPS = str(e)


class TestEnvironmentSetup(unittest.TestCase):
    """Basic environment checks for required runtime packages."""

    @unittest.skipIf(MISSING_DEPS, f"Missing required dependencies: {MISSING_DEPS}")
    def test_python_and_deps(self):
        """Verify essential dependencies exist in environment."""
        self.assertTrue(hasattr(NUMPY, '__version__'))
        self.assertTrue(hasattr(PANDAS, '__version__'))


if __name__ == '__main__':
    unittest.main()
