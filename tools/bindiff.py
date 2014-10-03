#!/usr/bin/env python

from libctf import bindiff
import sys

def usage():
	print "bindiff.py file1 file2"
def main(args):
	if (len(args) < 3):
		usage()
		return
	d1=open(args[1]).read()
	d2=open(args[2]).read()
	bindiff(d1, d2)


if __name__ == '__main__':
	main(sys.argv)