#!/usr/bin/env python3
import unittest
import subprocess
import os
from libctf import *

class TestShellcode(unittest.TestCase):
	process=None
	def setUp(self):
		if(sys.platform == "darwin"):
			config.os("osx")
		#config.verbose(True)
		path = os.path.abspath(__file__)
		path = os.sep.join((os.path.dirname(path), "shellcode"))
		self.process = subprocess.Popen([path], bufsize=0, stdin=subprocess.PIPE, stdout=subprocess.PIPE, close_fds=True, cwd=os.path.dirname(path))
	def tearDown(self):
		try:
			self.process.kill()
		except Exception:
			pass
		self.process.wait()
		self.process.stdin.close()
		self.process.stdout.close()
		del self.process
	def send_shellcode(self, asm):
		self.process.stdin.write(d(len(asm)))
		self.process.stdin.write(asm)
		
	def test_assemble(self):
		code = ";" + hexa(get_random(8)) + "\nret\n"
		asm = assemble(code)
		self.assertEqual(asm, b"\xc3")
		#test cache
		asm = assemble(code)
		self.assertEqual(asm, b"\xc3")

		code = ";" + hexa(get_random(8)) + "\nnotvalid eax, eax\n"
		self.assertRaises(Exception, assemble, code, printerrors=False)
	def test_has_badchar(self):
		ctx = Context(badchars=b"\x41")
		sc = ShellcodeSnippet(ctx=ctx)
		self.assertTrue(sc.has_badchar(0x41000000))
		self.assertTrue(sc.has_badchar(0x410000))
		self.assertTrue(sc.has_badchar(0x4100))
		self.assertTrue(sc.has_badchar(0x41))
		self.assertFalse(sc.has_badchar(0x42000000))
	def test_get_xor(self):
		ctx = Context(badchars=b"\x41")
		sc = ShellcodeSnippet(ctx=ctx)
		xor1,xor2 = sc.get_xor(0x41424344)
		self.assertFalse(sc.has_badchar(xor1))
		self.assertFalse(sc.has_badchar(xor2))
		self.assertEqual(0x41424344, xor1 ^ xor2)
	def testSyscall(self):
		asm = Syscall(1).assemble()
		hexa(asm)
	def testPushString(self):
		ctx = Context(badchars=b"\x00")
		asm = PushString("abcdefg", "eax", ctx=ctx).assemble()
		self.assertFalse(b"\x00" in asm)
		ctx = Context(badchars=b"\x00")
		asm = PushString("test", "eax", ctx=ctx).assemble()
		self.assertFalse(b"\x00" in asm)
	def testExit(self):
		asm = Exit(42).assemble()
		self.send_shellcode(asm)
		rc = self.process.wait()
		self.assertEqual(rc, 42)
	def testWrite(self):
		asm = Write(1, "Hello, world!").assemble()
		asm += Exit(0).assemble()
		self.send_shellcode(asm)
		data = self.process.stdout.read()
		self.assertEqual(data, b"Hello, world!")
	def testExecve(self):
		asm = Execve("/usr/bin/printf","Hello, World!").assemble()
		asm += Exit(0).assemble()
		self.send_shellcode(asm)
		data = self.process.stdout.read()
		self.assertEqual(data, b"Hello, World!")
	def testRead(self):
		asm = Read(0, "esp", len("Hello, World!")).assemble()
		asm += Write(1, "esp", len("Hello, World!")).assemble()
		asm += Exit(0).assemble()
		self.send_shellcode(asm)
		self.process.stdin.write(b"Hello, World!")
		data = self.process.stdout.read()
		self.assertEqual(data, b"Hello, World!")
	def testGetuid(self):
		asm = Getuid().assemble()
		asm += assemble("push eax\n")
		asm += Write(1, "esp", 4).assemble()
		asm += Exit(0).assemble()
		self.send_shellcode(asm)
		data = self.process.stdout.read()
		self.assertEqual(data, d(os.getuid()))
	def testSetuid(self):
		asm = Setuid(0).assemble()
		asm += assemble("push eax\n")
		asm += Write(1, "esp", 4).assemble()
		asm += Exit(0).assemble()
		self.send_shellcode(asm)
		data = self.process.stdout.read()
		self.assertEqual(data, d(0xffffffff))
