# shellcode utilities
import os
import tempfile
import subprocess
import struct

from cryptutils import md5
from langutils import switch
from textutils import chunkstring
import config
from constants import *

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
	filename = md5(header + code).encode("hex")[:8]
	path = os.path.join(tempfile.gettempdir(), "libctf")
	try:
		os.mkdir(path)
	except Exception:
		pass
	fullname = os.path.join(path, filename)
	try:
		binary = open(fullname).read()
		return binary
	except Exception:
		pass
	open(fullname + ".s", "w").write(header + code)
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
	return open(fullname).read()

class NotSupportedException(Exception):
	def __init__(self, cpu=None, OS=None):
		super(NotSupportedException, self).__init__("Arch %s/%s not supported"%(cpu, OS))

class _Register_Content(object):
	pass
"""Register content is undefined and can be wiped"""
REG_UNDEFINED=_Register_Content()
"""Register content is not a constant value and must not be erased"""
REG_RESERVED=_Register_Content()

all_registers_x86 = ["eax","ebx","ecx","edx","esi","edi","ebp","esp"]

class Context(object):
	cpu = None
	os = None
	state = None
	def __init__(self, cpu=None, OS=None):
		if cpu is not None:
			self.cpu = cpu
		else:
			self.cpu = config.cpu()
		if OS is not None:
			self.os = OS
		else:
			self.os = config.os()
		self.state = {}

class ShellcodeSnippet(object):
	def __init__(self, ctx=None):
		if ctx is not None:
			self.ctx = ctx
		else:
			self.ctx = Context()
	def assemble_x86(self):
		return None
	def assemble_amd64(self):
		return None
	def assemble_arm(self):
		return None
	def assemble_linux_x86(self):
		return None
	def assemble_linux_amd64(self):
		return None
	def assemble_linux_arm(self):
		return None
	def assemble(self):
		for case in switch(self.ctx.cpu):
			if case("x86"):
				asm = self.assemble_x86()
				if asm is not None:
					return asm
				break
			if case("amd64"):
				asm = self.assemble_amd64()
				if asm is not None:
					return asm
				break
			if case("arm"):
				asm = self.assemble_arm()
				if asm is not None:
					return asm
				break
		#fall through on more specialized assemblers
		for case in switch(self.ctx.os + "/" + self.ctx.cpu):
			if case("linux/x86"):
				asm = self.assemble_linux_x86()
				if asm is not None:
					return asm
			if case("linux/amd64"):
				asm = self.assemble_linux_amd64()
				if asm is not None:
					return asm
			if case("linux/arm"):
				asm = self.assemble_linux_arm()
				if asm is not None:
					return asm
			if case():
				raise NotSupportedException(cpu=self.ctx.cpu, OS=self.ctx.os)

	def __str__(self):
		return self.assemble()

class PushArray(ShellcodeSnippet):
	array = None
	dest = None
	def __init__(self, array, dest, ctx=None):
		"""push an array on the stack and return its value in dest register"""
		ShellcodeSnippet.__init__(self, ctx=ctx)
		self.array = array
		self.dest = dest
	def assemble_x86(self):
		code = ""
		#make a copy
		array = list(self.array)
		self.ctx.state[self.dest]=REG_RESERVED
		array.reverse()
		for v in array:
			if v in all_registers_x86:
				code += "push %s\n"%(v)
			else:
				code += "push %d\n"%(v)
		code += "mov %s, esp\n"%(self.dest)
		return assemble(code, cpu=self.ctx.cpu)

class PushString(ShellcodeSnippet):
	string = None
	dest = None
	def __init__(self, string, dest, ctx=None):
		"""push a string on the stack and return its value in dest register"""
		ShellcodeSnippet.__init__(self, ctx=ctx)
		self.string = string
		self.dest = dest
	def assemble_x86(self):
		#push string on stack
		values = chunkstring(self.string, 4)
		# pad the strings with zero
		values = map(lambda x: x+ "\x00" * (4-len(x)), values)
		# end the string with zero if it's not null terminated already
		if len(values)==0 or values[-1][3]!="\x00":
			values += [0]
		#convert to integer
		values = map(lambda x: struct.unpack("<I", x)[0], values)
		asm = PushArray(values, self.dest, ctx=self.ctx).assemble()
		return asm

class SetRegisters(ShellcodeSnippet):
	args = None
	def __init__(self, args, ctx=None):
		"""set data in registers. args is an array of (register, data) tupples"""
		super(SetRegisters, self).__init__(ctx=ctx)
		self.args = args
	def assemble_x86(self):
		asm = ""
		for reg, value in self.args:
			if value == REG_UNDEFINED:
				continue
			if value in all_registers_x86:
				# mov reg, reg
				if reg == value:
					continue
				asm += assemble("mov %s, %s\n"%(reg, value), cpu=self.ctx.cpu)
			elif type(value) == str:
				asm += PushString(string=value, dest=reg, ctx=self.ctx).assemble()
			elif type(value) == list or type(value) == tuple:
				asm += PushArray(array=value, dest=reg, ctx=self.ctx).assemble()
			elif value == 0:
				asm += assemble("xor %s,%s\n"%(reg, reg), cpu=self.ctx.cpu)
			elif value > 0 and value < 0x100:
				asm += assemble("push byte %d\npop %s\n"%(value, reg), 
					cpu=self.ctx.cpu)
			else:
				asm += assemble("mov %s,%d\n"%(reg, value), cpu=self.ctx.cpu)
			if type(value) == int:
				self.ctx.state[reg] = value
		return asm

class Syscall(ShellcodeSnippet):
	syscallnumber=0
	args = None
	def __init__(self, syscallnumber, ctx=None, args=[]):
		super(Syscall, self).__init__(ctx=ctx)
		self.syscallnumber = syscallnumber
		self.args = args
	def assemble_linux_x86(self):
		asm = SetRegisters(
				zip(["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp"],
					[self.syscallnumber] + list(self.args)
				),
				ctx=self.ctx
			).assemble()
			
		asm += assemble("int 0x80\n", cpu=self.ctx.cpu)
		self.ctx.state["eax"]=REG_UNDEFINED
		return asm

class Exit(ShellcodeSnippet):
	def __init__(self, errcode=0,ctx=None):
		super(Exit, self).__init__(ctx=ctx)
		self.errcode=errcode
	def assemble_linux_x86(self):
		return Syscall(ctx=self.ctx, syscallnumber=linux_x86_syscalls["exit"],
			args=[self.errcode]).assemble()

class Write(ShellcodeSnippet):
	fd = None
	data = None
	size = None
	def __init__(self, fd, data, size=0, ctx=None):
		super(Write, self).__init__(ctx=ctx)
		self.fd = fd
		self.data = data
		self.size = size
	def assemble_linux_x86(self):
		if type(self.data)==str and not self.data in all_registers_x86:
			size = len(self.data)
		else:
			size = self.size
		return Syscall(ctx=self.ctx, syscallnumber=linux_x86_syscalls["write"],
			args=[self.fd, self.data, size]).assemble()

class Read(ShellcodeSnippet):
	fd = None
	data = None
	size = None
	def __init__(self, fd, data, size, ctx=None):
		ShellcodeSnippet.__init__(self, ctx=ctx)
		self.fd = fd
		self.data = data
		self.size = size
	def assemble_linux_x86(self):
		return Syscall(syscallnumber=linux_x86_syscalls["read"],
			args=[self.fd, self.data, self.size], ctx=self.ctx).assemble()

class Execve(ShellcodeSnippet):
	filename = None
	arg = None
	def __init__(self, filename, arg=None, ctx=None):
		ShellcodeSnippet.__init__(self, ctx=ctx)
		self.filename = filename
		self.arg = arg
	def assemble_linux_x86(self):
		asm = ""
		asm += PushString(self.filename, "ebx", ctx=self.ctx).assemble()
		#environ
		asm += PushArray([0], "edx", ctx=self.ctx).assemble()
		#arg
		if self.arg != None:
			asm += PushString(self.arg, "ecx", ctx=self.ctx).assemble()
			asm += PushArray(["ebx", "ecx", 0], "ecx", ctx=self.ctx).assemble()
		else:
			asm += PushArray(["ebx", 0], "ecx", ctx=self.ctx).assemble()
		asm += Syscall(syscallnumber=linux_x86_syscalls["execve"], 
			args=["ebx","ecx","edx"], ctx=self.ctx).assemble()
		return asm

