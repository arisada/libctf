#!/usr/bin/env python

from textutils import *
from netutils import *
from cryptutils import *


def __assert__(x):
	if not x:
		 raise Exception("Assertion failed")

def test():
	__assert__(sha1("test") != None)
	__assert__(md5("test") != None)
	__assert__(sha256("test") != None)
	__assert__(d(0x41424344) == "DCBA")
	__assert__(w(0x4142) == "BA")
	#hexdump("A" * 15 + "HELLO" + "B" * 16, "HELLO")
	hexdump("ABCDEFGHAABB",["A", "AA"])
	#hexdump(sha256("test"))
	s = Buffer("abcd")
	__assert__(s[0:4] == "abcd")
	__assert__(s[:4] == "abcd")
	__assert__(s[1:] == "bcd")
	s[4] = 'e'
	s[5:7] = 'fg'
	s[0]="A"
	s[10]="K"
	s[7:]="hij"
	print s
	s[:11]="Hello"
	print s
	__assert__(type(s)==Buffer)
	s+=" World!"
	__assert__(type(s)==Buffer)
	print s
	print len(s)
	print s.encode("hex")
	#s="hello"
	__assert__(type(s)==Buffer)
	x = Buffer(length = 10)
	print x.encode("hex"), len(x)

	#aes test
	x = aes("A"*16, "B"*16)
	hexdump(x)
	hexdump(aes(x, "B"*16, decrypt=True))

	x = aes_cbc("A"*16, "B"*16, IV="C"*16)
	hexdump(x)
	hexdump(aes_cbc(x, "B"*16, IV="C"*16, decrypt=True))
	s=Socket("localhost",4444)
	s.connect()
	while True:
		r = s.readline(terminator="\r\n")
		if (r == None):
			break
		print "'%s'"%(r)
if __name__ == '__main__':
    test()
