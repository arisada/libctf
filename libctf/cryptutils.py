#!/usr/bin/env python

# sudo pip install pycrypto
import Crypto.Hash.SHA
import Crypto.Hash.SHA256
import Crypto.Hash.MD5
import Crypto.Cipher.AES
import sys
from .textutils import tobytes, byte, chunkstring

def sha1(x):
	return Crypto.Hash.SHA.SHA1Hash(tobytes(x)).digest()
def sha256(x):
	return Crypto.Hash.SHA256.SHA256Hash(tobytes(x)).digest()
def md5(x):
	return Crypto.Hash.MD5.MD5Hash(tobytes(x)).digest()
# AES in ECB mode
def aes(data, key, IV=b"", decrypt=False, mode=Crypto.Cipher.AES.MODE_ECB):
	hdl = Crypto.Cipher.AES.new(key, mode, IV)
	if(decrypt):
		return hdl.decrypt(data)
	else:
		return hdl.encrypt(data)

def aes_cbc(data, key, IV, decrypt=False):
	return aes(data, key, IV=IV, decrypt=decrypt, mode=Crypto.Cipher.AES.MODE_CBC)

def xor(data, key):
	"""Xor data with a repeated key"""
	paddedkey = key * (int(len(data)/len(key)) + 1)
	if sys.version_info >= (3, 0):
		if not isinstance(data, bytes) or not isinstance(key, bytes):
			raise TypeError("bytes input are required")
		return b"".join(byte(x^y) for (x,y) in zip(data,paddedkey))
	else:
		return b"".join(byte(ord(x)^ord(y)) for (x,y) in zip(data,paddedkey))


def sort_by_key(data):
	"""Sort a dictionary from values and return an array of (key, value) tuples"""
	array = [(k, data[k]) for k in data.keys()]
	array.sort(key=lambda x: x[1])
	return array

def freq_analysis(input, transform, evaluate, keyspace):
	"""Perform a bruteforce statistic attack on cipher transform
	and return an array of (freq, key)"""
	freq = []
	for k in keyspace:
		candidate = transform(input, k)
		score = evaluate(candidate)
		freq.append((score, k))
	freq.sort()
	return freq

def detect_ecb(data):
	keysizes = [8,16, 24, 32]
	# keysize, offset
	keyspace = [(i, j) for i in keysizes for j in range(i)]
	def transform(data, key):
		keysize, offset = key
		ret = chunkstring(data[offset:], keysize)
		ret = list(ret)
		if len(ret[-1]) != keysize:
			ret = ret[:-1]
		return ret
	def evaluate(data):
		data.sort()
		p = 0.0
		previous=None
		if len(data)==0:
			return 0.0
		for d in data:
			if d == previous:
				p += 1
			previous = d
		return p/len(data)
	probas = freq_analysis(data, transform, evaluate, keyspace)
	return probas[:-5:-1]

class distributions(object):
	class english(object):
		#source https://en.wikipedia.org/wiki/Letter_frequency
		letters = {
			b'a':0.08167,
			b'b':0.01492,
			b'c':0.02782,
			b'd':0.04253,
			b'e':0.12702,
			b'f':0.02228,
			b'g':0.02015,
			b'h':0.06094,
			b'i':0.06966,
			b'j':0.00153,
			b'k':0.00772,
			b'l':0.04025,
			b'm':0.02406,
			b'n':0.06749,
			b'o':0.07507,
			b'p':0.01929,
			b'q':0.00095,
			b'r':0.05987,
			b's':0.06327,
			b't':0.09056,
			b'u':0.02758,
			b'v':0.00987,
			b'w':0.02361,
			b'x':0.00150,
			b'y':0.01974,
			b'z':0.00074,
		}
		# http://www.data-compression.com/english.html defines space to be 0.1918
		letters_with_space = {k:v*(1-0.1918) for k,v in letters.items()}
		letters_with_space[' '] = 0.1918
		caps_letters = {k.upper():v*0.3 for k, v in letters.items()}
		letters_with_caps_space = letters_with_space.copy()
		letters_with_caps_space.update(caps_letters)
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
		if isinstance(i, str):
			h = ord(i) ^ ord(j)
		else:
			h = i ^ j
		sum += _bitcount_lookup[h & 0x0f] + _bitcount_lookup[h >> 4]
	return sum

class keyspace(object):
	letters=b"abcdefghijklmnopqrstuvwxyz"
	upperletters=b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	allletters=letters+upperletters
	ciphers=b"0123456789"
	lettersciphers=letters+ciphers
	alllettersciphers=allletters+ciphers
	specials=b' !_&~/*-+\\<>$^%[]{}#"\'|:,?.='
	allprintable=alllettersciphers + specials
	@staticmethod
	def generate(space, size):
		"""generator that yeld keys part of the keyspace"""
		state = [0] * size
		max = len(space) - 1
		finished = False
		while not finished:
			#print state
			s = map(lambda x: space[x], state)
			yield "".join(s)
			for i in range(size-1, -1, -1):
				if i == 0 and state[i] == max:
					finished = True
				if state[i] == max:
					state[i] = 0
				else:
					state[i] = state[i] + 1
					break

def get_random(size):
	"""Return (size) bytes of secure random data"""
	try:
		with open("/dev/urandom", mode="rb") as f:
			return f.read(size)
	except Exception:
		with open("/dev/random", mode="rb") as f:
			return f.read(size)

def extendedEuclid(a, b):
    """return a tuple of three values: x, y and z, such that x is
    the GCD of a and b, and x = y * a + z * b"""
    if a == 0:
        return b, 0, 1
    else:
        g, y, x = extendedEuclid(b % a, a)
        return g, x - (b // a) * y, y

def modInv(a, m):
    """returns the multiplicative inverse of a in modulo m as a
       positive value between zero and m-1"""
    # notice that a and m need to co-prime to each other.
    linearCombination = extendedEuclid(a, m)
    return linearCombination[1] % m

def modExp(a, d, n):
    """returns a ** d (mod n)"""
    return pow(a, d, n)

class RSA(object):
	private=False
	phi=None
	n=None
	p=None
	q=None
	e=None
	d=None
	def __init__(self, n=None, p=None, q=None, e=None):
		if n==None and (p==None or q==None):
			raise Exception("At least n or p+q should be provided")
		if(e == None):
			raise Exception("e should be provided")
		self.n=n
		self.p=p
		self.q=q
		self.e=e
		if (self.n == None):
			self.n = p * q
		else:
			if p is not None and q is not None and self.n != p*q:
				raise Exception("n doesn't match p*q")
		if p != None and q != None:
			self.private = True
			self.phi = (p-1)*(q-1)
			self.d = modInv(self.e, self.phi)
	def sign(self, message):
		signature = modExp(message, self.d, self.n)
		return signature
	def verify(self, message, signature):
		return message == modExp(signature, self.e, self.n)
	def encrypt(self, message):
		return modExp(message, self.e, self.n)
	def decrypt(self, crypted):
		return modExp(crypted, self.d, self.n)
