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

class keyspace(object):
	letters="abcdefghijklmnopqrstuvwxyz"
	upperletters="ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	allletters=letters+upperletters
	ciphers="0123456789"
	lettersciphers=letters+ciphers
	alllettersciphers=allletters+ciphers
	specials='''!_&~/*-+\\<>$^%[]{}#"\'|:,?.='''
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
			for i in xrange(size-1, -1, -1):
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
		return open("/dev/urandom").read(size)
	except Exception:
		return open("/dev/random").read(size)

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
