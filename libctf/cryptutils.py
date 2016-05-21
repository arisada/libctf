#!/usr/bin/env python

# sudo pip install pycrypto
import Crypto.Hash.SHA
import Crypto.Hash.SHA256
import Crypto.Hash.MD5
import Crypto.Cipher.AES
import sys
import math
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

def pkcs7(data, blocksize):
	"""Apply pkcs7 padding to the data"""
	padding = blocksize - (len(data)%blocksize)
	if sys.version_info >= (3,0):
		return data + bytes([padding] * padding)
	else:
		return data + chr(padding)*padding

def pkcs7_unpad(data):
	if sys.version_info >= (3,0):
		padding = data[-1]
		if data[-padding:] != bytes([padding] * padding):
			raise Exception("Invalid padding %d"%(padding))
	else:
		padding = ord(data[-1])
		if data[-padding:] != chr(padding) * padding:
			raise Exception("Invalid padding %d"%(padding))

	return data[:-padding]

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
	keysizes = [8,16]
	# keysize, offset
	keyspace = [(i, j) for i in keysizes for j in range(i)]
	def transform(data, key):
		keysize, offset = key
		ret = chunkstring(data[offset:], keysize)
		ret = list(ret)
		if len(ret) == 0:
			return ret
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

def find_ecb(oracle, cleartext=b'A'*16):
	"""Call an ECB oracle with known cleartext to find the offsets where
	cleartext is encrypted.
	returns (blocksize, cleartext_offset, encrypted_offset)
	blocksize is the detected block size of the cipher
	cleartext_offset is the amount of bytes needed before going in the first whole controlled block
	encrypted_offset is the offset of the first block wholy controlled"""
	block1 = oracle(b'')
	for i in range(1, 48):
		block = oracle(b'A'*i)
		if len(block) != len(block1):
			blocksize = len(block) - len(block1)
			break
	else:
		raise Exception("Ciphertext doesn't grow with cleartext")
	pattern = None
	data = oracle(cleartext*3)
	blocks = chunkstring(data, blocksize)
	for i in range(len(blocks)):
		for j in range(i+1, len(blocks)):
			if blocks[i] == blocks[j]:
				pattern = blocks[i]
				break
	if pattern is None:
		raise Exception("Cipher is not ECB")
	for offset in range(blocksize):
		enc = oracle(b'B'*offset + cleartext)
		if pattern in enc:
			encoffset = enc.find(pattern)
			break
	else:
		raise Exception("Couldn't find offset")
	return (blocksize, offset, encoffset)

def ecb_crack(oracle, debug=False, key_space=None):
	"""Implement an attack on an encryption oracle
	oracle(input)
	where its implementation is doing ECB(random||ourinput||secret)
	and returns the ECB encrypted output."""
	if(debug):
		hexdump(oracle(b''))
	if key_space == None:
		key_space = keyspace.allprintable + b'\n'

	blocksize, clear_offset, enc_offset = find_ecb(oracle)
	print("blocksize %d, encrypted offset %d, %d prepad bytes needed"%(blocksize, enc_offset, clear_offset))

	len1 = len(oracle(b"A"*clear_offset))
	for clearlen in range(1, 17):
		len2 = len(oracle(b"A"*(clear_offset + clearlen)))
		if len2 != len1:
			secret_len = len2 - blocksize - clearlen - enc_offset
			break

	print("secret_len: %d"%(secret_len))
	# we cannot decrypt before the start of choosen ciphertext
	prepad=b'B' * clear_offset
	secret = b""
	# start with an array of byteshifted ciphertexts
	ciphertexts = [oracle(prepad + b'A' * i)[enc_offset:] for i in range(blocksize)]

	for block in range((len1 +1) // blocksize):
		for offset in range(blocksize):
			block1 = ciphertexts[blocksize - offset -1][block*blocksize:(block+1)*blocksize]
			#print (hexa(block1))
			for j in key_space:
				# last blocksize-1 bytes of secret
				p = secret[-blocksize+1:]
				p = b'A' * (blocksize - len(p) - 1) + p
				candidate = p + byte(j)
				#hexdump(candidate)
				block2 = oracle(prepad + candidate)[enc_offset:][:blocksize]
				if block1 == block2:
					if(debug):
						print("Found %s"%(repr(chr(j))))
					secret += byte(j)
					if len(secret) == secret_len:
						return secret
					break
			else:
				print("Character not found :(")
				return secret

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

def product(factors):
	"""multiply an interable of numbers together"""
	p = 1
	for f in factors:
		p *= f
	return p

_primes = [2, 3, 5, 7, 11, 13]

def _test_prime(p):
	"""test if p is divisible by any prime of the list"""
	for i in _primes:
		if p%i == 0:
			return False
	return True

def all_primes(limit):
	"""return a generator on all primes below or equal to a limit.
	Will only consume memory for returned elements"""
	limited = (p for p in _primes if p <= limit)
	for p in limited:
		yield p
	p = _primes[-1] + 2
	while(p <= limit):
		if _test_prime(p):
			_primes.append(p)
			yield p
		p += 2

def factorize(v, limit=None):
	"""non-efficient factorization algorithm"""
	factors = []
	if limit is not None:
		primes = all_primes(limit)
	else:
		primes = all_primes(math.sqrt(v) + 1)
	for p in primes:
		#print(p)
		while(v%p ==0):
			factors.append(p)
			v = v // p
		if v == 1:
			return factors
	return factors + [v]

def isqrt(n):
	"""returns the biggest x such as x*x <= n"""
	x = n
	y = (x + 1) // 2
	while y < x:
		x = y
		y = (x + n // x) // 2
	return x

def find_invpow(x,n):
	"""Finds the integer component of the n'th root of x,
	an integer such that y ** n <= x < (y + 1) ** n.
	"""
	high = 1
	while high ** n < x:
		high *= 2
	low = high//2
	while low < high:
		mid = (low + high) // 2
		if low < mid and mid**n < x:
			low = mid
		elif high > mid and mid**n > x:
			high = mid
		else:
			return mid
	return mid + 1

def gcd(a, b):
	while a != 0:
		a, b = b%a, a
	return b

def lcm(a, b):
	return (a*b)//gcd(a,b)

def extendedEuclid(a, b):
	x,y, u,v = 0,1, 1,0
	while a != 0:
		q, r = b//a, b%a
		m, n = x-u*q, y-v*q
		b,a, x,y, u,v = a,r, u,v, m,n
	return b, x, y

def modInv(a, m):
    """returns the multiplicative inverse of a in modulo m as a
       positive value between zero and m-1"""
    # notice that a and m need to co-prime to each other.
    linearCombination = extendedEuclid(a, m)
    return linearCombination[1] % m

def modExp(a, d, n):
    """returns a ** d (mod n)"""
    return pow(a, d, n)

def chinese_remainder(a, n):
	"""Find the chinese remainder of a list of a_i mod n_i"""
	s = 0
	prod = product(n)
	for a_i, n_i in zip(a, n):
		p = prod // n_i
		s += a_i * modInv(p, n_i) * p
	return s % prod

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
