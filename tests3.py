#!/usr/bin/env python3

import unittest

if __name__ == '__main__':
	# to test a single case:
	# python -m unittest tests.TestShellcode.testSetuid
	testsuite = unittest.TestLoader().discover('tests/')
	unittest.TextTestRunner(verbosity=1).run(testsuite)

