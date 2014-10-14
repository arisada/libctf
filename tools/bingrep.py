#!/usr/bin/env python
from libctf import hexdump, cdecode, bingrep

import argparse

def main():
	parser = argparse.ArgumentParser(description="Grep for binary files")
	parser.add_argument('pattern', nargs=1, help='pattern, C encoding', metavar="pattern")
	parser.add_argument('-B', help='Show LINES lines of context before', metavar="LINES")
	parser.add_argument('-A', help='Show LINES lines of context after', metavar="LINES")
	parser.add_argument('files', nargs='*', metavar='FILE')
	args = parser.parse_args()
	before = 0
	after = 0
	if args.A != None:
		after = int(args.A)
	if args.B != None:
		before = int(args.B)
	patterns = map(cdecode, args.pattern)

	for f in args.files:
		if (len(args.files) > 1):
			print "%s:"%(f)
		data=open(f).read()
		found = bingrep(data, patterns=patterns, linesbefore = before, linesafter=after)
		if not found:
			print "No match in %s"%(f)
		

if __name__ == '__main__':
	main()