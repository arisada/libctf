#!/usr/bin/env python

from textutils import *
from textutils import _merge_offsets
from netutils import *
from cryptutils import *

import unittest
import threading


class TestCrypto(unittest.TestCase):
	cleartext = "A"*16
	IV = "B"*16
	key = "C" * 16

	def test_md5(self):
		x = md5("Aris").encode("hex")
		self.assertEqual(x, "6a9e32c39e3dedf6dceb96f0dac0ffdd")
	def test_sha1(self):
		x = sha1("Aris").encode("hex")
		self.assertEqual(x, "564ab1b32a47ae3ac7d3f9ad2c2dbdf2a1df2076")
	def test_sha256(self):
		x = sha256("Aris").encode("hex")
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
	def test_xor(self):
		x = xor(data="AAAA", key="AAAA")
		self.assertEqual(x, "\x00" * 4)
		x = xor(data="A", key="AAAA")
		self.assertEqual(x, "\x00")
		x = xor(data="AAAA", key="A")
		self.assertEqual(x, "\x00"*4)
		x = xor(data="AAAA", key="AAAAZZZZZZZZZZZ")
		self.assertEqual(x, "\x00"*4)

class TestPack(unittest.TestCase):
	def test_pack(self):
		self.assertEqual(d(0x41424344), "DCBA")
		self.assertEqual(w(0x4142), "BA")
	def test_cencode(self):
		self.assertEqual(cencode("\x41\xff\x32"), '"\\x41\\xff\\x32"')
	def test_cdecode(self):
		orig = "ABC\xff\t\r\n"
		encoded = "\\x41BC\\xff\\t\\r\\n"
		self.assertEqual(cdecode(encoded), orig)
		self.assertRaises(TypeError, cdecode, "xxxx\\x")
		self.assertRaises(TypeError, cdecode, "xxxx\\x4")
		self.assertRaises(TypeError, cdecode, "xxxx\\x4z4141")
		self.assertRaises(TypeError, cdecode, "xxxx\\")
		self.assertRaises(TypeError, cdecode, "xxxx\\z")
	def test_tocdeclaration(self):
		orig = "ABCD"
		encoded = 'uint8_t name[4] = \n\t"\\x41\\x42\\x43\\x44";\n'
		self.assertEqual(tocdeclaration("name",orig), encoded)

class TestHexdump(unittest.TestCase):
	def test_output(self):
		s = "A" * 15 + "HELLO" + "B" * 16
		out = hexdump(s, "HELLO", output="string")
		expected = "00000000: 41 41 41 41 41 41 41 41  41 41 41 41 41 41 41 48  AAAAAAAAAAAAAAAH\n" + \
			"00000010: 45 4c 4c 4f 42 42 42 42  42 42 42 42 42 42 42 42  ELLOBBBBBBBBBBBB\n" + \
			"00000020: 42 42 42 42                                       BBBB            \n"

		out = out.replace('\033[91m', "").replace('\033[0m',"")
		self.assertEqual(out, expected)
		#print out
	def test_bindiff(self):
		s1 = "A" * 15 + "HELLO" + "B" * 16
		s2 = "A" * 15 + "WORLD" + "B" * 16
		out = bindiff(s1,s2, output="string")
		expected = "00000000: 41414141414141414141414141414148 AAAAAAAAAAAAAAAH" + \
		"  41414141414141414141414141414157 AAAAAAAAAAAAAAAW\n" + \
		"00000010: 454c4c4f424242424242424242424242 ELLOBBBBBBBBBBBB" + \
		"  4f524c44424242424242424242424242 ORLDBBBBBBBBBBBB\n"
		out = out.replace('\033[91m', "").replace('\033[0m',"")
		self.assertEqual(out, expected)
		s2 += "And the rest!"
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

class TestTextSocket(unittest.TestCase):
	ready = threading.Event()
	thread = None

	def setUp(self):
		self.ready.clear()
		self.thread = threading.Thread(target=self.textserver, args=())
		self.thread.start()
		self.ready.wait()

	def tearDown(self):
		self.thread.join()
		del self.thread
		self.ready.clear()

	def textserver(self):
		try:
			bindsocket=BindSocket(port=4444)
		except:
			self.ready.set()
			bindsocket.close()
			return
		self.ready.set()
		s = bindsocket.accept(timeout=1.0)
		s.send("Hello\n")
		s.send("How is it going?\r\n")
		s.send("finishedTERMINATOR")
		s.readline(timeout=1)
		s.close()
		bindsocket.close()

	def test_lines(self):
		s = Socket("localhost", 4444)
		s.connect()
		txt = s.readline()
		self.assertEqual(txt, "Hello")
		txt = s.readline("\r\n")
		self.assertEqual(txt, "How is it going?")
		txt = s.readline("TERMINATOR")
		self.assertEqual(txt, "finished")
		s.send("Finished\n")
		txt = s.readline()
		self.assertEqual(txt, None)
		s.close()

	def test_len(self):
		s = Socket("localhost",4444)
		s.connect()
		txt = s.read_block(len("Hello\n"))
		self.assertEqual(txt, "Hello\n")
		txt = s.read_block(len("How is it going?\r\n"))
		self.assertEqual(txt, "How is it going?\r\n")
		s.send("Finished\n")
		s.close()

	def test_poll(self):
		s = Socket("localhost",4444)
		s.connect()
		(r,w,x) = s.poll(read=True, exception=True, timeout=1.0)
		self.assertEqual((r,w,x), (True, False, False))
		# Now socket should have data to read and clear to send
		(r,w,x) = s.poll(read=True, write=True, exception = True, timeout=0.0)
		self.assertEqual((r,w,x), (True, True, False))
		s.readline()
		s.readline()
		s.readline("TERMINATOR")
		# now socket should be empty
		(r,w,x) = s.poll(read=True, write=True, exception = True, timeout=0.0)
		self.assertEqual((r,w,x), (False, True, False))
		s.send("Finished\n")
		s.close()
	def test_timeout(self):
		s = Socket("localhost",4444)
		s.connect()
		self.assertRaises(TimeoutException, s.read_block, 1000, 0.2)
		s.close()

class TestBindSocket(unittest.TestCase):
	def test_timeout(self):
		s= BindSocket("::",4444)
		self.assertRaises(TimeoutException, s.accept, 0.2)

if __name__ == '__main__':
    unittest.main()
