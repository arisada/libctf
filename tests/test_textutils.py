#!/usr/bin/env python3
import unittest
from libctf import *
from libctf.textutils import _merge_offsets


class TestPack(unittest.TestCase):
	def test_pack(self):
		self.assertEqual(d(0x41424344), b"DCBA")
		self.assertEqual(w(0x4142), b"BA")
	def test_cencode(self):
		self.assertEqual(cencode(b"\x41\xff\x32"), '"\\x41\\xff\\x32"')
	def test_cdecode(self):
		orig = b"ABC\xff\t\r\n"
		encoded = "\\x41BC\\xff\\t\\r\\n"
		self.assertEqual(cdecode(encoded), orig)
		self.assertRaises(TypeError, cdecode, "xxxx\\x")
		self.assertRaises(TypeError, cdecode, "xxxx\\x4")
		self.assertRaises(TypeError, cdecode, "xxxx\\x4z4141")
		self.assertRaises(TypeError, cdecode, "xxxx\\")
		self.assertRaises(TypeError, cdecode, "xxxx\\z")
	def test_tocdeclaration(self):
		orig = b"ABCD"
		encoded = 'uint8_t name[4] = \n\t"\\x41\\x42\\x43\\x44";\n'
		self.assertEqual(tocdeclaration("name",orig), encoded)
	def test_byte(self):
		self.assertEqual(byte(1), b'\x01')
	def test_hexa(self):
		h = hexa(b"\x41\x00\xff")
		self.assertEqual(h, "4100ff")
	def test_hexdecode(self):
		b = hexdecode("4100ff")
		self.assertEqual(b, b'\x41\x00\xff')

class TestHexdump(unittest.TestCase):
	def test_output(self):
		s = b"A" * 15 + b"HELLO" + b"B" * 16 + b"\x00"
		out = hexdump(s, b"HELLO", output="string")
		expected = "00000000: 41 41 41 41 41 41 41 41  41 41 41 41 41 41 41 48  AAAAAAAAAAAAAAAH\n" + \
			"00000010: 45 4c 4c 4f 42 42 42 42  42 42 42 42 42 42 42 42  ELLOBBBBBBBBBBBB\n" + \
			"00000020: 42 42 42 42 00                                    BBBB.           \n"

		out = out.replace('\033[91m', "").replace('\033[0m',"")
		self.assertEqual(out, expected)
		#print out
	def test_bindiff(self):
		s1 = b"A" * 15 + b"HELLO" + b"B" * 16
		s2 = b"A" * 15 + b"WORLD" + b"B" * 16
		out = bindiff(s1,s2, output="string")
		expected = "00000000: 41414141414141414141414141414148 AAAAAAAAAAAAAAAH" + \
		"  41414141414141414141414141414157 AAAAAAAAAAAAAAAW\n" + \
		"00000010: 454c4c4f424242424242424242424242 ELLOBBBBBBBBBBBB" + \
		"  4f524c44424242424242424242424242 ORLDBBBBBBBBBBBB\n"
		out = out.replace('\033[91m', "").replace('\033[0m',"")
		self.assertEqual(out, expected)
		s2 += b"And the rest!"
		out = bindiff(s1,s2, output="string")
		#print "\n" + out
		expected = "00000000: 41414141414141414141414141414148 AAAAAAAAAAAAAAAH" + \
		"  41414141414141414141414141414157 AAAAAAAAAAAAAAAW\n" + \
		"00000010: 454c4c4f424242424242424242424242 ELLOBBBBBBBBBBBB" + \
		"  4f524c44424242424242424242424242 ORLDBBBBBBBBBBBB\n" + \
		"00000020: 42424242                         BBBB              " + \
		"42424242416e64207468652072657374 BBBBAnd the rest\n" + \
		"00000030:                                                    " + \
		"21                               !               \n"
		out = out.replace('\033[91m', "").replace('\033[0m',"")
		self.assertEqual(out, expected)
	def test_bindifftable(self):
		s1 = "A"*15 + "BCD" + "A"*15
		s2 = "A"*15 + "AAA" + "A"*14 + "B" + "DEF"
		table = bindifftable(s1, s2)
		expected = [
			(15, "BCD", "AAA"),
			(32, "A", "B"),
			(33, "", "DEF")
		]
		self.assertEqual(table, expected)
	def test_alloccurences(self):
		s = "ABCDEFGHIJKL"
		offsets = all_occurences(s,["E", "IJ", "Z", "ABC"])
		self.assertEqual(offsets, [(0,3),(4,1),(8,2)])
	def test_mergeoffsets(self):
		self.assertEqual(_merge_offsets([(0,5),(5,1)]), [(0,6)])
		self.assertEqual(_merge_offsets([(0,5),(0,6)]), [(0,6)])
		self.assertEqual(_merge_offsets([(0,6),(3,1)]), [(0,6)])
		self.assertEqual(_merge_offsets([(4,1),(5,1)]), [(4,2)])
		self.assertEqual(_merge_offsets([(1,2),(2,1),(3,1)]), [(1,3)])
		self.assertEqual(_merge_offsets([]), [])

class TestInrange(unittest.TestCase):
	def test_inrange(self):
		testset = [
			[(0,1),(1,2), False],
			[(0,1),(0,2), True],
			[(0,1),(0,1), True],
			[(0,1),(0,0), True],
			[(0,1),(3,4), False],
			[(0,10), (5,10), True],
			[(0,10), (5,9), True],
			[(5,10), (4,6), True]
		]
		for a,b,t in testset:
			self.assertEqual(in_range(a,b), t)
			self.assertEqual(in_range(b,a), t)

class TestText(unittest.TestCase):
	def test_replace(self):
		s=replace("Hi, folks!", ("Hi","Hello"), ("folks","world"))
		self.assertEqual(s, "Hello, world!")
	def test_remove(self):
		s=remove("Gimme an A, Gimme a B, Gimme an ABC", "ABC", "B", "A")
		self.assertEqual(s, "Gimme an , Gimme a , Gimme an ")

class TestBuffer(unittest.TestCase):
	def setUp(self):
		self.s = Buffer("abcd")
	def test_get(self):
		self.assertEqual(self.s[0:4], b"abcd")
		self.assertEqual(self.s[:4], b"abcd")
		self.assertEqual(self.s[1:], b"bcd")

	def test_assign(self):
		self.s[4] = 'e'
		self.assertEqual(self.s, b"abcde")
		self.s[5:7] = 'fg'
		self.assertEqual(self.s, b"abcdefg")
		self.s[0]="A"
		self.assertEqual(self.s, b"Abcdefg")
		self.s[10]="K"
		self.assertEqual(self.s, b"Abcdefg\x00\x00\x00K")
		self.s[7:]="hij"
		self.assertEqual(self.s, b"AbcdefghijK")
		self.s[:11]="Hello"
		self.assertEqual(self.s, b"AbcdefHello")
		self.s[:4]="XY"
		self.assertEqual(self.s, b"AbXYefHello")
		self.assertIsInstance(self.s, Buffer)
		self.s += " World!"
		self.assertEqual(self.s, b"AbXYefHello World!")

	def test_len(self):
		self.assertEqual(len(self.s), 4)
		self.s = Buffer(length=10)
		self.assertEqual(len(self.s), 10)

	def test_encode(self):
		self.assertEqual(self.s.encode("hex"), "61626364")

if __name__ == '__main__':
	unittest.main()
