#!/usr/bin/env python3
import unittest
from libctf import *

class TestLangUtils(unittest.TestCase):
	def test_maxsortedlist(self):
		x = MaxSortedList(maxn=3)
		x.append(1)
		x.append(2)
		x.append(3)
		self.assertEqual(x, [3, 2, 1])
		x.append(0)
		self.assertEqual(x, [3, 2, 1])
		x.append(2)
		self.assertEqual(x, [3, 2, 2])
		x.append(4)
		self.assertEqual(x, [4, 3, 2])
		self.assertEqual(x[0], 4)
		self.assertEqual(x[2], 2)
		self.assertEqual(len(x), 3)
		self.assertEqual(str(x), "[4, 3, 2]")
	def test_nameddict(self):
		d = {'a':1, 'b':2, 'c':3}
		n = NamedDict(d)
		self.assertEqual(d, n)
		self.assertEqual(n["a"], 1)
		self.assertEqual(n.a, 1)
		n.a = 4
		self.assertNotEqual(d, n)
		self.assertEqual(n["a"], 4)
		self.assertEqual(n.a, 4)

if __name__ == '__main__':
	unittest.main()
