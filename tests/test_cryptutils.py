#!/usr/bin/env python3
import unittest
from libctf import *

class TestCrypto(unittest.TestCase):
	cleartext = b"A"*16
	IV = b"B"*16
	key = b"C" * 16

	def test_md5(self):
		x = hexa(md5("Aris"))
		self.assertEqual(x, "6a9e32c39e3dedf6dceb96f0dac0ffdd")
	def test_sha1(self):
		x = hexa(sha1("Aris"))
		self.assertEqual(x, "564ab1b32a47ae3ac7d3f9ad2c2dbdf2a1df2076")
	def test_sha256(self):
		x = hexa(sha256("Aris"))
		self.assertEqual(x,"b114ebc3ed13bfbef292395f009659771b56edb1e9be848bcdcd0fbfd6b24f4a")
	def test_aes(self):
		x = aes(self.cleartext, self.key)
		y = aes(x, self.key, decrypt = True)
		self.assertEqual(self.cleartext, y)
		self.assertNotEqual(x, self.cleartext)
	def test_aes_cbc(self):
		x = aes_cbc(self.cleartext, self.key, IV=self.IV)
		y = aes_cbc(x, self.key, decrypt = True, IV=self.IV)
		self.assertEqual(self.cleartext, y)
		self.assertNotEqual(x, self.cleartext)
	def test_xor(self):
		x = xor(data=b"AAAA", key=b"AAAA")
		self.assertEqual(x, b"\x00" * 4)
		x = xor(data=b"A", key=b"AAAA")
		self.assertEqual(x, b"\x00")
		x = xor(data=b"AAAA", key=b"A")
		self.assertEqual(x, b"\x00"*4)
		x = xor(data=b"AAAA", key=b"AAAAZZZZZZZZZZZ")
		self.assertEqual(x, b"\x00"*4)
	def test_pkcs7(self):
		data = b'A'*12
		out = pkcs7(data, 16)
		self.assertEqual(out, b'AAAAAAAAAAAA\x04\x04\x04\x04')
	def test_pkcs7_unpad(self):
		data = pkcs7_unpad(b'AAAAAAAAAAAA\x04\x04\x04\x04')
		self.assertEqual(data, b'A'*12)
	def test_random(self):
		r = get_random(8)
		self.assertEqual(len(r), 8)
	def test_distribution_english_letters(self):
		sum = 0.0
		for i in distributions.english.letters.values():
			sum += i
		epsilon = 1.0e-3
		self.assertTrue(sum > 1.0 - epsilon and sum < 1.0 + epsilon)
	def test_distribution_english_letters_space(self):
		sum = 0.0
		for i in distributions.english.letters_with_space.values():
			sum += i
		epsilon = 1.0e-3
		self.assertTrue(sum > 1.0 - epsilon and sum < 1.0 + epsilon)

	def test_sort_by_key(self):
		x = {'a':1, 'b':2, 'c':0, 'd':-1}
		y = sort_by_key(x)
		self.assertEqual(y, [('d',-1), ('c', 0), ('a', 1), ('b', 2)])
	def test_hamming(self):
		x = b"this is a test"
		y = b"wokka wokka!!!"
		self.assertEqual(hamming(x,y), 37)
	def test_count_bits(self):
		x = "ABCDEFG"
		y = "\x00" * len(x)
		h = hamming(x, y)
		self.assertEqual(count_bits_set(x), h)
	def test_product(self):
		p = product([2, 3, 3, 5, 13, 29, 37])
		self.assertEqual(p, 2*3*3*5*13*29*37)
	def test_all_primes(self):
		primes = list(all_primes(30))
		self.assertEqual(primes, [2, 3, 5, 7, 11, 13, 17, 19, 23, 29])
	def test_factorize(self):
		factors = [2, 3, 3, 5, 13, 29, 37]
		r = factorize(product(factors))
		self.assertEqual(r, factors)
	def test_isqrt(self):
		vals = (2, 3, 5, 10, 23, 213, 325234, 2342352354, 324234234)
		for i in vals:
			x = isqrt(i*i)
			self.assertEqual(x, i)
		for i in vals:
			x = isqrt(i*i + 1)
			self.assertEqual(x, i)
	def test_find_invpow(self):
		vals = (3, 5, 10, 23, 213, 325234, 2342352354, 324234234)
		# find_invpow doesn't work with x=2
		for e in (2, 3, 4):
			for i in vals:
				x = find_invpow(int(i**e), e)
				self.assertEqual(x, i)
	def test_gcd(self):
		f1 = product((2,3,3,5))
		f2 = product((2,3,11))
		self.assertEqual(gcd(f1,f2), 2*3)
	def test_lcm(self):
		f1 = product((2,3,3,5))
		f2 = product((2,3,11))
		self.assertEqual(lcm(f1,f2), 2*3*3*5*11)
	def test_chinese(self):
		value = 1337
		n = [7, 13, 29]
		result = chinese_remainder([value % n_i for n_i in n], n)
		self.assertEqual(result, value)
	def test_RSA(self):
		p = 22307
		q = 93179
		pub = RSA(n=p*q, e=65537)
		priv = RSA(p=p, q=q, e=65537)
		msg = 31337
		sig = priv.sign(msg)
		self.assertTrue(pub.verify(msg, sig))
		self.assertFalse(pub.verify(msg, sig + 1))

		cipher = pub.encrypt(msg)
		self.assertEqual(priv.decrypt(cipher), msg)

if __name__ == '__main__':
	unittest.main()
