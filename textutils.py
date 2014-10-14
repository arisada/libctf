#!/usr/bin/env python

import struct
import sys

def d(x):
	"""Pack to uint32"""
	return struct.pack("<I", x)

def w(x):
	"""Pack to uint16"""
	return struct.pack("<H", x)

def cencode(s):
	"""Encode to \\x encoding"""
	ret = ''.join(map(lambda x:"\\x"+x.encode("hex"), s))
	return '"' + ret + '"'
def cdecode(s):
	"""Decode a \\x encoding"""
	transform = {
		"\\" : "\\",
		"n":"\n",
		"r":"\r",
		"t":"\t"
	}
	ret = ""
	i = 0
	while i < len(s):
		if s[i] != '\\':
			ret += s[i]
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
		ret += s[i+1:i+3].decode("hex")
		i += 3
	return ret
def __isprintable__(c):
	val = ord(c)
	if(val >= 0x20 and val < 0x80):
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
	for i in xrange(len(line[:8])):
		c = "%.2x"%(ord(line[i]))
		if (mask[i]):
			s += color(c, "red")
		else:
			s += c
		s+= "" if short else " "

	s+= "" if short else " "
	# Print second half of hex dump
	for i in xrange(len(line[8:])):
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
	for i in xrange(len(line)):
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
	if isinstance(patterns, basestring):
		patterns = [patterns]
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

def _merge_offsets(offsetlist):
	"""merge a list of offsets so they are the minimal set and
	there is no overlap."""
	#courtesy https://stackoverflow.com/questions/5679638/
	#merging-a-list-of-time-range-tuples-that-have-overlapping-time-ranges
	if len(offsetlist) == 0:
		return offsetlist
	# change the map from (offset, len) to (start, stop)
	initialrange = map(lambda (x,y):(x,x+y), offsetlist)
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
	return map(lambda (x,y):(x,y-x), f)

def hexdump(data, highlight = None, output="print", printoffset=0):
	"""output hexdump data with highlight on strings in highlight list"""
	#gen = m_hexdump.hexdump(data, result="generator")
	out = ""
	offsets = all_occurences(data, highlight)
	#print offsets
	# convert to a bit mask 
	mask = [False] * len(data)
	for (index, length) in offsets:
		for i in xrange(length):
			mask[index + i] = True
	#print mask

	index = 0
	while index < len(data):
		x = data[index:index+16]
		# Print the offset
		s = "%.8x: "%(index + printoffset)
		s += __hexdata(x, mask[index:index+16])
		if (output == "print"):
			print s
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
	mask = map(lambda (x,y): x != y, zip(d1,d2))
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
				print s
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

	for i in xrange(totallen):
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
			print " --"
	if output == "string":
		return out
	else:
		return len(offsets) != 0

# attempt to do sorta mutable strings
class Buffer(object):
	s=""
	def __init__(self, s="", length=0):
		if (s != "" and length != 0):
			raise Exception("One of s or length must be set")
		if length == 0:
			self.s = s
		else:
			self.s = "\0"*length
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
			self.s += chr(0) * (x.stop - len(self.s))
		self.s = self.s[:x.start] + y + self.s[x.stop:]
	def __eq__(self, x):
		return self.s.__eq__(x)
	def __str__(self):
		return self.s.__str__()
	def __add__(self, x):
		return Buffer(self.s.__add__(x))
	def __len__(self):
		return self.s.__len__()
	def encode(self, x):
		return self.s.encode(x)
	def decode(self, x):
		return self.s.decode(x)
	def join(self, x, y):
		return self.s.join(x, y)
	def find(self, sub, start=None, end=None):
		return self.s.find(sub, start, end)

