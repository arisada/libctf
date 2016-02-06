#!/usr/bin/env python

import struct
import sys
import codecs

def d(x):
	"""Pack to uint32"""
	return struct.pack("<I", x)

def w(x):
	"""Pack to uint16"""
	return struct.pack("<H", x)

def unpack32(x):
	"""unpack from uint32"""
	return struct.unpack("<I", x)[0]

def cencode(s):
	"""Encode to \\x encoding"""
	ret = ''.join(map(lambda x:"\\x"+hexa(byte(x)), s))
	return '"' + ret + '"'
def cdecode(s):
	"""Decode a \\x encoding"""
	transform = {
		"\\": b"\\",
		"n": b"\n",
		"r": b"\r",
		"t": b"\t"
	}
	ret = b""
	i = 0
	while i < len(s):
		if s[i] != '\\':
			ret += tobytes(s[i])
			i += 1
			continue
		if len(s[i:]) < 2:
			raise TypeError("Invalid \\ encoding")
		i += 1
		c = s[i]
		if c in transform.keys():
			ret += transform[c]
			i += 1
			continue
		if c != 'x':
			raise TypeError("Invalid \\ encoding")
		if len(s[i+1:]) < 2:
			raise TypeError("Invalid \\ encoding")
		try:
			ret += codecs.decode(s[i+1:i+3], "hex")
		except Exception:
			raise TypeError("Invalid \\x encoding")
		i += 3
	return ret

def tobytes(s):
	if isinstance(s, bytes):
		return s
	if sys.version_info >= (3, 0):
		return bytes(s, "ascii")
	else:
		return s

def byte(i):
	"""convert an integer to a byte value"""
	if sys.version_info >= (3, 0):
		return bytes((i,))
	elif isinstance(i, str):
		return i
	else:
		return chr(i)
	
def hexa(s):
	"""portable hexa conversion"""
	if sys.version_info >= (3, 0):
		if isinstance(s, str):
			s = bytes(s, "ascii")
		return codecs.encode(s, "hex").decode('ascii')
	else:
		return s.encode("hex")

def chunkstring(string, length):
	#split a string by length
	return (string[0+i:length+i] for i in range(0, len(string), length))

def tocdeclaration(name, value, type="uint8_t", indent="\t", width=60):
	out = "%s %s[%d] = \n"%(type, name, len(value))
	s = cencode(value).replace('"',"")
	for i in chunkstring(s, width):
		out += indent + '"' + i + '"\n'
	#add the ; at the end but before \n
	out = out[:-1] + ';\n'
	return out

def __isprintable__(c):
	val = ord(c)
	if(val >= 0x20 and val < 0x7f):
		return True
	return False

# Do not write colors out of tty
__tty__= sys.stdout.isatty()

def color(string, color="red"):
	colors = {
		"red":'\033[91m',
		"green":'\033[92m'
	}
	ENDC= '\033[0m'
	if __tty__:
		return colors[color] + string + ENDC
	else:
		return string

def __hexdata(line, mask, short=False):
	s = ""
	# Print first half of hex dump
	for i in range(len(line[:8])):
		c = "%.2x"%(ord(line[i]))
		if (mask[i]):
			s += color(c, "red")
		else:
			s += c
		s+= "" if short else " "

	s+= "" if short else " "
	# Print second half of hex dump
	for i in range(len(line[8:])):
		c = "%.2x"%(ord(line[8 + i]))
		if (mask[i + 8]):
			s += color(c, "red")
		else:
			s += c
		s+= "" if short else " "

	if (len(line) < 16):
		if short:
			s += " " * 2 * (16-len(line))
		else:
			s += " " * 3 * (16-len(line))
	s+= " "
	# Print ascii part
	for i in range(len(line)):
		if __isprintable__(line[i]):
			c=line[i]
		else:
			c="."
		if mask[i]:
			s += color(c, "red")
		else:
			s += c
	# complete ascii line if incomplete
	if len(line) < 16:
		s += " " * (16 - len(line))
	return s

def all_occurences(data, patterns, merged=False):
	"""Find all occurence of patterns in data
	Returns a list of (offset, len) tuples.	"""
	offsets = []
	# if the patterns is a string, make it an array
	if isinstance(patterns, str):
		patterns = [tobytes(patterns)]
	elif isinstance(patterns, bytes):
		patterns = [patterns]
	else:
		patterns = (tobytes(i) for i in patterns)
	data = tobytes(data)
	# get the (offset, len) of every match in data
	if patterns != None:
		for p in patterns:
			index = data.find(p)
			while index != -1:
				offsets.append((index, len(p)))
				index = data.find(p, index +1)
	offsets.sort()
	if (merged):
		offsets = _merge_offsets(offsets)
	return offsets

def replace(s, *args):
	"""replace all substrings in string with replacements.
	usage: replace("Hi, folks!", ("Hi","Hello"), ("folks","world"))"""
	for w,r in args:
		s = s.replace(w,r)
	return s

def remove(s, *args):
	"""remove all substring in string, starting from the left and
	to the right."""
	for w in args:
		s = s.replace(w,"")
	return s

def _merge_offsets(offsetlist):
	"""merge a list of offsets so they are the minimal set and
	there is no overlap."""
	#courtesy https://stackoverflow.com/questions/5679638/
	#merging-a-list-of-time-range-tuples-that-have-overlapping-time-ranges
	if len(offsetlist) == 0:
		return offsetlist
	initialrange = [(x, x+y) for (x,y) in offsetlist]
	i = sorted(set([tuple(sorted(x)) for x in initialrange]))

	# initialize final ranges to [(a,b)]
	f = [i[0]]
	for c, d in i[1:]:
		a, b = f[-1]
		if c<=b<d:
			f[-1] = a, d
		elif b<c<d:
			f.append((c,d))
		else:
			pass
	return [(x, y-x) for (x, y) in f]
def in_range(a,b):
	"""Return true if the two tuple parameters (begin, end) overlap"""
	a0, an = a
	b0, bn = b
	#   [AAAAAAAAA]
	#  BBBBBB          1
	#       BBB        2
	#           BBBBBB 3
	#   BBBBBBBBBBBBB  4
	if b0 >= a0 and b0 < an:
		#2,3,4
		return True
	if b0 <= a0 and bn > a0:
		#1,4
		return True
	return False

def hexdump(data, highlight = None, output="print", printoffset=0):
	"""output hexdump data with highlight on strings in highlight list"""
	#gen = m_hexdump.hexdump(data, result="generator")
	out = ""
	offsets = all_occurences(data, highlight)
	#print offsets
	# convert to a bit mask 
	mask = [False] * len(data)
	for (index, length) in offsets:
		for i in range(length):
			mask[index + i] = True
	#print mask

	index = 0
	while index < len(data):
		x = data[index:index+16]
		# Print the offset
		s = "%.8x: "%(index + printoffset)
		s += __hexdata(x, mask[index:index+16])
		if (output == "print"):
			print (s)
		else:
			out += s + "\n"
		index += 16
	if (output == "string"):
		return out

def bindiff(d1, d2, onlydiff=True, output="print"):
	"""Output an hexdump diff of two binary strings, with highlight of differences
	if onlydiff=True: do only show different lines"""
	totallen = max(len(d1), len(d2))
	# create a mask of differences
	mask = [x != y for (x,y) in zip(d1, d2)]
	mask += [True] * abs(len(d1) - len(d2))
	
	index = 0
	out = ""
	while index < totallen:
		# Print the offset
		x1 = d1[index:index+16]
		x2 = d2[index:index+16]
		if not onlydiff or x1 != x2:
			s = "%.8x: "%(index)
			s += __hexdata(x1, mask[index:index+16], short=True)
			s += "  "
			s += __hexdata(x2, mask[index:index+16], short=True)

			if (output == "print"):
				print (s)
			else:
				out += s + "\n"
		index += 16
	if (output == "string"):
		return out

def bindifftable(d1, d2):
	"""Output a list of tupples (offset, orig, new) of the differences between d1 and d2"""
	table = []
	totallen = min(len(d1), len(d2))
	offset = None
	orig = ""
	new =""

	for i in range(totallen):
		a = d1[i]
		b = d2[i]
		if offset != None:
			if a != b:
				orig +=a
				new +=b
			else:
				table.append((offset, orig, new))
				offset, orig, new = None, "",""
		else:
			if a != b:
				offset = i
				orig = a
				new = b
	if offset != None:
		table.append((offset, orig, new))
	if len(d2) > totallen:
		table.append((totallen, "", d2[totallen:]))
	elif len(d1) > totallen:
		raise Exception("cannot shrink in patches")
	return table 

def bingrep(d, patterns, linesbefore=0, linesafter=0, output="print"):
	offsets = all_occurences(d, patterns, merged = True)
	parts = []
	out = ""
#	print offsets
	for start, stop in offsets:
		stop = start + stop
		start = (start & ~0xf) - (linesbefore * 16)
		if start < 0: start = 0
		stop = (stop & ~0xf) + (linesafter +1) * 16
#		print (start, stop)
		parts.append((start, stop - start))
	# Remerge the parts, because there might be some new overlaps
	parts = _merge_offsets(parts)
	First = False
	for start, l in parts:
		r = hexdump(d[start:start+l], highlight=patterns, printoffset=start, output=output)
		if (output == "string"):
			out += r
		if len(parts) > 1 and parts[-1] != (start, l):
			print (" --")
	if output == "string":
		return out
	else:
		return len(offsets) != 0

# attempt to do sorta mutable strings
class Buffer(object):
	s=b""
	def __init__(self, s=b"", length=0):
		if (s != b"" and length != 0):
			raise Exception("One of s or length must be set")
		if length == 0:
			if isinstance(s, bytes):
				self.s = s
			else:
				self.s = tobytes(s)
		else:
			self.s = b"\0"*length
	def __getitem__(self, x):
		return self.s.__getitem__(x)
	def __setitem__(self, x, y):
		if isinstance(x, int):
			x = slice(x, x+1, None)
		if (x.stop == None):
			x = slice(x.start, x.start + len(y))
		if (x.start == None):
			x = slice(x.stop - len(y), x.stop)
		#print x
		if (x.stop - x.start != len(y)):
			raise Exception("Replacement string (%d) too big for range[%d:%d]"%(len(y),x.start, x.stop))
		if x.stop > len(self.s):
			self.s += b"\x00" * (x.stop - len(self.s))
		self.s = self.s[:x.start] + tobytes(y) + self.s[x.stop:]
	def __eq__(self, x):
		return self.s.__eq__(x)
	def __str__(self):
		return self.s.__str__()
	def __add__(self, x):
		return Buffer(self.s + tobytes(x))
	def __len__(self):
		return self.s.__len__()
	def encode(self, x):
		return codecs.decode(codecs.encode(self.s, x), "ascii")
	def decode(self, x):
		return self.s.decode(x)
	def join(self, x, y):
		return self.s.join(x, y)
	def find(self, sub, start=None, end=None):
		return self.s.find(sub, start, end)

