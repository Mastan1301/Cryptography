from fastecdsa import keys, curve, ecdsa
from Crypto.Cipher import AES
import os
from Crypto.Protocol.KDF import PBKDF2
import rsa as RSA

class rsa():
	def __init__(self):
		pass
	def gen_key():
		(priv, pub) = RSA.newkeys(1024)
		return (priv, pub)
	def encrypt1(message, publickey):
		encrypted = RSA.encrypt(message, publickey)
		return encrypted
	def decrypt1(ciphertext, priv):
		return RSA.decrypt(ciphertext, priv)

BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]

class ecc():
	def __init__(self):
		pass

	def gen_key():
		return keys.gen_keypair(curve.P256)

	def get_sign(msg, priv_key):
		return ecdsa.sign(msg, priv_key)

	def verify(msg, r, s, pub_key):
		try:
			valid = ecdsa.verify((r, s), msg, pub_key)
			return msg
		except fastecdsa.ecdsa.EcdsaError:
			return False

class aes():
	def __init__(self):
		pass

	def gen_key():
		salt = b"this is a salt"
		kdf = PBKDF2('some', salt, 64, 1000)
		key = kdf[:32]
		return key

	def init_vector():
		return os.urandom(16)

	def encrypt1(msg, key, iv):
		msg = pad(msg)
		aes1 = AES.new(key, AES.MODE_CBC, iv)
		encd = aes1.encrypt(msg)
		return encd

	def decrypt1(encd, key, iv):
		aes1 = AES.new(key, AES.MODE_CBC, iv)
		decd = aes1.decrypt(encd)
		return unpad(decd).decode("utf-8")








'''from fastecdsa import keys, curve, ecdsa
from Cryptodome.Cipher import AES


class ecc():
	def __init__(self):
		pass

	def gen_key():
		return keys.gen_keypair(curve.P256)

	def get_sign(msg, priv_key):
		return ecdsa.sign(msg, priv_key)

	def verify(msg, r, s, pub_key):
		try:
			valid = ecdsa.verify((r, s), msg, pub_key)
			return True
		except fastecdsa.ecdsa.EcdsaError:
			return False

	def test():
		priv, pub = ecc.gen_key()
		message = "This is CRIOT"
		(r, s) = ecc.get_sign(message, priv)
		if ecc.verify(message, r, s, pub):
			print("Authenticated")
			text = message
			print(text)
		else:
			print("Malicious")


class aes():
	def __init__(self):
		pass

	def gen_key():
		return

	def encrypt(msg, key):
		cipher = AES.new(key, AES.MODE_EAX)
		nonce = cipher.nonce
		ciphertext, tag = cipher.encrypt_and_digest(msg)
		return (ciphertext, tag)

	def decrypt(cipher, ciphertext, tag):
		text = cipher.decrypt(ciphertext)
		try:
			cipher.verify(tag)
			return True
		except ValueError:
			return False'''
