#!/usr/bin/env python
import socket
import select
import sys

class TimeoutException(Exception):
	pass

# socket class
class Socket(object):
	s = None
	readbuffer = b""
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
	def send(self, x, encoding="utf-8"):
		if not isinstance(x, bytes):
			x = bytes(x, encoding)
		return self.s.send(x)
	def __wait_recv__(self, timeout):
		if (timeout != None):
			(r,w,x) = self.poll(read=True, exception=True, timeout=timeout)
			if not r and not x:
				raise TimeoutException("recv: timeout")
		
	def recv(self, length=0, timeout=None):
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
			return None
		if length == 0:
			length = 4096
		self.__wait_recv__(timeout)
		ret = self.s.recv(length)
		if len(ret) == 0:
			self.eof = True
		return ret
	def read_block(self, length, timeout=None):
		"""Blocking read of length bytes"""
		while len(self.readbuffer) < length and not self.eof:
			self.__wait_recv__(timeout)
			r = self.s.recv(4096)
			if len(r) == 0:
				self.eof = True
				break
			self.readbuffer += r
		ret = self.readbuffer[:length]
		self.readbuffer = self.readbuffer[length:]
		return ret

	def readline(self, terminator=b"\n", timeout=None):
		"""Read a complete line until EOF. Returns None when finished"""
		while self.readbuffer.find(terminator) < 0 and \
			not self.eof:
			self.__wait_recv__(timeout)
			r = self.s.recv(4096)
			if len(r) == 0:
				self.eof = True
				break
			self.readbuffer += r
		if self.eof and self.readbuffer == b"":
			return None
		index = self.readbuffer.find(terminator)
		if index < 0:
			ret = self.readbuffer
			self.readbuffer = b""
			return ret
		ret = self.readbuffer[:index]
		self.readbuffer = self.readbuffer[index + len(terminator):]
		return ret
	def poll(self, read=True, write=False, exception=False, timeout=0.0):
		"""Poll the socket for read, write or except event. Timeout in seconds.
		Returns tupple of booleans"""
		if (not read and not write and not exception):
			raise Exception("Invalid arguments")
		rlist, wlist, xlist = [],[],[]
		if read: rlist.append(self.s)
		if write: wlist.append(self.s)
		if exception: xlist.append(self.s)
		rlist,wlist,xlist = select.select(rlist, wlist, xlist, timeout)
		return (len(rlist) > 0, len(wlist) > 0, len(xlist) > 0)

	def close(self):
		self.s.close()
		del self.s
	def expect(self, data, timeout=None):
		"""loop until data is found on the socket"""
		s=b""
		while s.find(data) < 0:
			r = self.recv(timeout=timeout)
			if r != None:
				s+=r
			else:
				return None
		if s.find(data) >= 0:
			self.readbuffer=s[s.find(data) + len(data):]
			return s[:s.find(data) + len(data)]
		return None

	def interactConsole(self):
		while True:
			rlist = (self.s, sys.stdin)
			wlist = ()
			xlist = (self.s, sys.stdin)
			rlist,wlist,xlist = select.select(rlist, wlist, xlist, 30)
			if(len(xlist) > 0):
				break
			if self.s in rlist:
				data = self.recv()
				if data == None:
					break
				sys.stdout.write(str(data, 'latin1'))
			if sys.stdin in rlist:
				data = sys.stdin.readline()
				self.send(data)

class BindSocket(object):
	s = None
	def __init__(self, bindhost="::", port=0):
		self.s = socket.socket(socket.AF_INET6)
		self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.s.bind((bindhost, port))
		self.s.listen(5)
	def accept(self, timeout = None):
		if (timeout != None):
			rlist, wlist, xlist = select.select([self.s], [self.s], [self.s], timeout)
			#print rlist, wlist, xlist
			if len(rlist)==0 and len(wlist)==0 and len(xlist)==0:
				raise TimeoutException("Accept: timeout")

		new = self.s.accept()
		return Socket(new[1][0], new[1][1], sock=new[0])
	def close(self):
		self.s.close()
		del self.s
