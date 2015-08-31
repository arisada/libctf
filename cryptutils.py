#!/usr/bin/env python

# sudo pip install pycrypto
import Crypto.Hash.SHA
import Crypto.Hash.SHA256
import Crypto.Hash.MD5
import Crypto.Cipher.AES


def sha1(x):
	return Crypto.Hash.SHA.SHA1Hash(x).digest()
def sha256(x):
	return Crypto.Hash.SHA256.SHA256Hash(x).digest()
def md5(x):
	return Crypto.Hash.MD5.MD5Hash(x).digest()
# AES in ECB mode
def aes(data, key, IV="", decrypt=False, mode=Crypto.Cipher.AES.MODE_ECB):
	hdl = Crypto.Cipher.AES.new(key, mode, IV)
	if(decrypt):
		return hdl.decrypt(data)
	else:
		return hdl.encrypt(data)

def aes_cbc(data, key, IV, decrypt=False):
	return aes(data, key, IV=IV, decrypt=decrypt, mode=Crypto.Cipher.AES.MODE_CBC)


def xor(data, key):
	"""Xor data with a repeated key"""
	paddedkey = key * (len(data)/len(key) + 1)
	return "".join(map(lambda (x,y):chr(ord(x)^ord(y)), zip(data,paddedkey)))

def sort_by_key(data):
	"""Sort a dictionary from values and return an array of (key, value) tuples"""
	def cmp(x, y):
		if (x[1] == y[1]):
			return 0
		elif (x[1] > y[1]):
			return 1
		else:
			return -1
	array = [(k, data[k]) for k in data.keys()]
	array.sort(cmp = cmp)
	return array

class distributions(object):
	class english(object):
		#source https://en.wikipedia.org/wiki/Letter_frequency
		letters = {
			'a':0.08167,
			'b':0.01492,
			'c':0.02782,
			'd':0.04253,
			'e':0.12702,
			'f':0.02228,
			'g':0.02015,
			'h':0.06094,
			'i':0.06966,
			'j':0.00153,
			'k':0.00772,
			'l':0.04025,
			'm':0.02406,
			'n':0.06749,
			'o':0.07507,
			'p':0.01929,
			'q':0.00095,
			'r':0.05987,
			's':0.06327,
			't':0.09056,
			'u':0.02758,
			'v':0.00987,
			'w':0.02361,
			'x':0.00150,
			'y':0.01974,
			'z':0.00074,
		}
		# http://www.data-compression.com/english.html defines space to be 0.1918
		letters_with_space = {k:v*(1-0.1918) for k,v in letters.items()}
		letters_with_space[' '] = 0.1918

_bitcount_lookup = [
	0, 1, 1, 2, 1, 2, 2, 3,
	1, 2, 2, 3, 2, 3, 3, 4
]

def count_bits_set(x):
	"""count how many bits are set in the x string"""
	sum = 0
	for i in x:
		a, b = ord(i) & 0x0f, (ord(i) & 0xf0) >> 4
		sum += _bitcount_lookup[a] + _bitcount_lookup[b]
	return sum

def hamming(a,b):
	"""return the hamming distance between a and b"""
	sum = 0
	for i,j in zip(a,b):
		h = ord(i) ^ ord(j)
		sum += _bitcount_lookup[h & 0x0f] + _bitcount_lookup[h >> 4]
	return sum
