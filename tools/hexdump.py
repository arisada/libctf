#!/usr/bin/env python

from libctf import hexdump

import argparse

def main():
	parser = argparse.ArgumentParser(description="Hexdumping a binary files")
	parser.add_argument('-H', help='highlight', metavar="pattern")
	parser.add_argument('-o', help='start hexdumping at OFFSET', metavar="OFFSET")
	parser.add_argument('-l', help='Limit to LINES lines', metavar="LINES")
	parser.add_argument('file', nargs=1, metavar='FILE')
	args = parser.parse_args()
	data=open(args.file[0]).read()
	if args.o != None:
		if args.o.startswith("0x"):
			offset=int(args.o, 16)
		else:
			offset = int(args.o)
		data = data[offset:]
	else:
		offset=0
	if args.l != None:
		data = data[:int(args.l) * 16]
	hexdump(data, highlight=args.H, printoffset=offset)	

if __name__ == '__main__':
	main()