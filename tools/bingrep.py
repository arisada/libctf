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
	data=open(args.files[0]).read()
	patterns = map(cdecode, args.pattern)
	before = 0
	after = 0
	if args.A != None:
		after = int(args.A)
	if args.B != None:
		before = int(args.B)
	bingrep(data, patterns=patterns, linesbefore = before, linesafter=after)	

if __name__ == '__main__':
	main()