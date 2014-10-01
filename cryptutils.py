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

