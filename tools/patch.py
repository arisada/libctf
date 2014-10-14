#!/usr/bin/env python
from libctf import cdecode, Buffer, all_occurences

import argparse

def main():
	parser = argparse.ArgumentParser(description="Patch a binary files")
	parser.add_argument('File', nargs=1, help='File to patch', metavar="FILE")
	parser.add_argument('-i', action="store_true", help='Patch in-line')
	parser.add_argument('-p', help='Patch a pattern instead of an offset', metavar="PATTERN")
	parser.add_argument('-o', help='Output file', metavar="FILE")
	parser.add_argument('-O', help="Patch at offset", metavar="OFFSET")
	parser.add_argument('Value', nargs=1, help='Value to patch with', metavar="DATA")
	
	args = parser.parse_args()
	if (not args.i and args.o == None) or (args.o != None and args.i):
		print "One of -i or -o must be used"
		return
	if args.p == args.O == None or (args.p != None and args.O != None):
		print "one of -p or -O must be used"
		return
	value = cdecode(args.Value[0])
	f = open(args.File[0])
	data = Buffer(f.read())
	f.close()
	if args.p != None:
		pattern = cdecode(args.p)
		if len(pattern) != len(value):
			print "Length mismatch: cannot patch %d bytes with %d"%(len(pattern),len(value))
			return
		offsets = all_occurences(data, pattern)
	else:
		if args.O.startswith("0x"):
			offset = int(args.O, 16)
		else:
			offset = int(args.O)

		offsets = [(offset, len(value))]

	if len(offsets)==0:
		print "No match found"
		return
	for start, l in offsets:
		print "Patching 0x%.8x:%d bytes"%(start, l)
		data[start:start+l] = value
	if args.i:
		f = open(args.File[0], "w")
	else:
		f = open(args.o, "w")
	f.write(str(data))
	f.close()
	
if __name__ == '__main__':
	main()