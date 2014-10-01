#!/usr/bin/env python
import socket

# socket class
class Socket(object):
	s = None
	readbuffer = ""
	eof = False
	destination = None
	def __init__(self, host, port, sock=None):
		if sock != None:
			self.s = sock
		else:
			self.s = socket.socket(socket.AF_INET)
			self.destination = (host, port)

	def connect(self):
		return self.s.connect(self.destination)
	def send(self, x):
		return self.s.send(x)
	def recv(self, length=0):
		"""Read length bytes from socket, return when data available"""
		if len(self.readbuffer) > 0:
			if length == 0:
				l = len(self.readbuffer)
			else:
				l = min(len(self.readbuffer), length)
			ret = self.readbuffer[:l]
			self.readbuffer = self.readbuffer[l:]
			return ret
		if self.eof:
			return 0
		if length == 0:
			length = 4096
		ret = self.s.recv(length)
		if len(ret) == 0:
			self.eof = True
	def read_block(self, length):
		"""Blocking read of length bytes"""
		while len(self.readbuffer) < length and not self.eof:
			r = self.s.recv(4096)
			if len(r) == 0:
				self.eof = True
				break
			self.readbuffer += r
		ret = self.readbuffer[:length]
		self.readbuffer = self.readbuffer[length:]
		return ret

	def readline(self, terminator="\n"):
		"""Read a complete line until EOF. Returns None when finished"""
		while self.readbuffer.find(terminator) < 0 and \
			not self.eof:
			r = self.s.recv(4096)
			if len(r) == 0:
				self.eof = True
				break
			self.readbuffer += r
		if self.eof and self.readbuffer == "":
			return None
		index = self.readbuffer.find(terminator)
		if index < 0:
			ret = self.readbuffer
			self.readbuffer = ""
			return ret
		ret = self.readbuffer[:index]
		self.readbuffer = self.readbuffer[index + len(terminator):]
		return ret
	def close(self):
		self.s.close()
		del self.s

class BindSocket(object):
	s = None
	def __init__(self, bindhost="::", port=0):
		self.s = socket.socket(socket.AF_INET6)
		self.s.bind((bindhost, port))
		self.s.listen(5)
	def accept(self):
		new = self.s.accept()
		return Socket(new[1][0], new[1][1], sock=new[0])
	def close(self):
		self.s.close()
		del self.s
