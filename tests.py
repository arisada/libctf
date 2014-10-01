#!/usr/bin/env python

from textutils import *
from netutils import *
from cryptutils import *

import unittest


class TestCrypto(unittest.TestCase):
	cleartext="A"*16
	IV = "B"*16
	key = "C" * 16

	def test_md5(self):
		x=md5("Aris").encode("hex")
		self.assertEqual(x, "6a9e32c39e3dedf6dceb96f0dac0ffdd")
	def test_sha1(self):
		x=sha1("Aris").encode("hex")
		self.assertEqual(x, "564ab1b32a47ae3ac7d3f9ad2c2dbdf2a1df2076")
	def test_sha256(self):
		x=sha256("Aris").encode("hex")
		self.assertEqual(x,"b114ebc3ed13bfbef292395f009659771b56edb1e9be848bcdcd0fbfd6b24f4a")
	def test_aes(self):
		x = aes(self.cleartext, self.key)
		y = aes(x, self.key, decrypt = True)
		self.assertEqual(self.cleartext, y)
		self.assertNotEqual(x, self.cleartext)
	def test_aes_cbc(self):
		x = aes_cbc(self.cleartext, self.key, IV=self.IV)
		y = aes_cbc(x, self.key, decrypt = True, IV=self.IV)
		self.assertEqual(self.cleartext, y)
		self.assertNotEqual(x, self.cleartext)

class TestPack(unittest.TestCase):
	def test_pack(self):
		self.assertEqual(d(0x41424344), "DCBA")
		self.assertEqual(w(0x4142), "BA")

class TestHexdump(unittest.TestCase):
	def test_output(self):
		s = "A" * 15 + "HELLO" + "B" * 16
		out = hexdump(s, "HELLO", output="string")
		expected = "00000000: 41 41 41 41 41 41 41 41  41 41 41 41 41 41 41 48  AAAAAAAAAAAAAAAH\n" + \
			"00000010: 45 4c 4c 4f 42 42 42 42  42 42 42 42 42 42 42 42  ELLOBBBBBBBBBBBB\n" + \
			"00000020: 42 42 42 42                                       BBBB\n"

		out = out.replace('\033[91m', "").replace('\033[0m',"")
		self.assertEqual(out, expected)
		#print out
	
class TestBuffer(unittest.TestCase):
	def setUp(self):
		self.s = Buffer("abcd")
	def test_get(self):
		self.assertEqual(self.s[0:4], "abcd")
		self.assertEqual(self.s[:4], "abcd")
		self.assertEqual(self.s[1:], "bcd")

	def test_assign(self):
		self.s[4] = 'e'
		self.assertEqual(self.s, "abcde")
		self.s[5:7] = 'fg'
		self.assertEqual(self.s, "abcdefg")		
		self.s[0]="A"
		self.assertEqual(self.s, "Abcdefg")
		self.s[10]="K"
		self.assertEqual(self.s, "Abcdefg\x00\x00\x00K")
		self.s[7:]="hij"
		self.assertEqual(self.s, "AbcdefghijK")
		self.s[:11]="Hello"
		self.assertEqual(self.s, "AbcdefHello")
		self.s[:4]="XY"
		self.assertEqual(self.s, "AbXYefHello")
		self.assertIsInstance(self.s, Buffer)
		self.s += " World!"
		self.assertEqual(self.s, "AbXYefHello World!")

	def test_len(self):
		self.assertEqual(len(self.s), 4)
		self.s = Buffer(length=10)
		self.assertEqual(len(self.s), 10)

	def test_encode(self):
		self.assertEqual(self.s.encode("hex"), "61626364")



class TestDummy(unittest.TestCase):
	def setUp(self):
		self.test=1234
	def test_xxx(self):
		self.assertEqual(1,1)
		self.assertTrue(True)

def __assert__(x):
	if not x:
		 raise Exception("Assertion failed")

def test():

	#aes test
	s=Socket("localhost",4444)
	s.connect()
	while True:
		r = s.readline(terminator="\r\n")
		if (r == None):
			break
		print "'%s'"%(r)

#if __name__ == '__main__':
#    test()


if __name__ == '__main__':
    unittest.main()

