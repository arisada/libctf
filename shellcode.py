# shellcode utilities
from cryptutils import md5
import os
import tempfile
import subprocess

def assemble(code, cpu="x86", printerrors=True):
	"""Assemble given code to binary. Accepted cpus: "x86","amd64",
	"arm"."""
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

