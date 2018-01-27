#!/usr/bin/env python3
import unittest
from libctf import *
from libctf.elf import *

dir_path = os.path.dirname(__file__)

class TestParsing(unittest.TestCase):
	def setUp(self):
		class ElfMock(object):
			def __init__(self, data):
				self.data = data
			def read(self, nbytes, offset = None):
				return self.data[:nbytes]
			get = Elf.get
		self.elf = ElfMock(b'\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7')

	def test_get_32_little(self):
		self.elf.endian = '<'
		self.assertEqual(self.elf.get(Elf32_Addr), 0xf3f2f1f0)
		self.assertEqual(self.elf.get(Elf32_Half), 0xf1f0)
		self.assertEqual(self.elf.get(Elf32_Sword), -0xc0d0e10)

class TestElf32(unittest.TestCase):
	def setUp(self):
		self.elf = open_elf_file(os.path.join(dir_path, 'libc_32.so'))
	def test_header(self):
		print (header_print(self.elf.ehdr))
		print("Sections")
		for i in self.elf.s_headers:
			print(header_print(i))
		print("Program headers")
		for i in self.elf.p_headers:
			print (header_print(i))
		self.assertEqual(self.elf.ehdr.type, ET_DYN)
		self.assertEqual(self.elf.ehdr.machine, EM_386)
		self.assertEqual(self.elf.ehdr.entry, 0x19670)


	def tearDown(self):
		self.elf.close()

if __name__ == '__main__':
	unittest.main()
