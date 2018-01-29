#!/usr/bin/env python
import socket
import select
import sys
import time
import socket
import serial
import serial.tools.list_ports

class TimeoutException(Exception):
	pass

class Stream(object):
	def __init__(self, throttle=None):
		self.s = None
		self.throttle = throttle
		self.eof = False
		self.readbuffer = b''

	def send(self, x, encoding="utf-8"):
		if not isinstance(x, bytes):
			x = bytes(x, encoding)
		if self.throttle is None:
			return self.__do_send__(x)
		else:
			r = 0
			for i in x:
				r += self.__do_send__(bytes((i,)))
				time.sleep(self.throttle)
			return r

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
			length = self.bufsize
		self.__wait_recv__(timeout)
		ret = self.__do_recv__(length)
		if len(ret) == 0:
			self.eof = True
		return ret

	def read_block(self, length, timeout=None):
		"""Blocking read of length bytes"""
		while len(self.readbuffer) < length and not self.eof:
			self.__wait_recv__(timeout)
			r = self.__do_recv__(self.bufsize)
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
			r = self.__do_recv__(self.bufsize)
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

	def expect(self, data, timeout=None):
		"""loop until data is found on the socket"""
		s=b""
		while s.find(data) < 0:
			try:
				r = self.recv(timeout=timeout)
			except TimeoutException as e:
				self.readbuffer=s
				raise e
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
			#print(rlist,wlist,xlist)
			if(len(xlist) > 0):
				break
			if self.s in rlist:
				data = self.recv()
				if data == None:
					break
				sys.stdout.write(str(data, 'latin1'))
				sys.stdout.flush()
			if sys.stdin in rlist:
				data = sys.stdin.readline()
				self.send(data)

# socket class
class Socket(Stream):
	bufsize = 4096
	def __init__(self, host, port, sock=None, throttle=None):
		"""throtle: send bytes one by one and wait throttle s. in between"""
		super(Socket, self).__init__(throttle=throttle)
		if sock != None:
			self.s = sock
			self.destination = None
		else:
			self.s = socket.socket(socket.AF_INET)
			self.destination = (host, port)

	def connect(self):
		return self.s.connect(self.destination)
	def disable_nagle(self):
		self.s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
	def __do_send__(self, data):
		return self.s.send(data)
	def __do_recv__(self, length):
		return self.s.recv(length)

	def close(self):
		self.s.close()
		del self.s

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

class Serial(Stream):
	bufsize = 1
	def __init__(self, baudrate=115200, device=None, connect=True, reset_on_open=False, throttle=None):
		"""throtle: send bytes one by one and wait throttle s. in between"""
		super(Serial, self).__init__(throttle=throttle)
		self.device = device
		self.baudrate = baudrate
		self.reset_on_open = reset_on_open
		if(connect):
			self.connect()

	def connect(self):
		if self.device is None:
			ports = serial.tools.list_ports.comports()
			if len(ports)==0:
				raise Exception("No serial port found")
			devices = [p.device for p in ports if not "Bluetooth" in p.device]
			self.device = devices[0]
		if not self.reset_on_open:
			# everything I tried failed.
			pass
		self.s = serial.Serial(port = self.device, baudrate = self.baudrate)

	def __do_send__(self, data):
		w = self.s.write(data)
		self.s.flush()
		return w
	def __do_recv__(self, length):
		#Possible bug: read will not stop until timeout or length bytes read.
		return self.s.read(length)

	def close(self):
		self.s.close()
		del self.s

	def reset(self):
		"""Send a DTR to reset the board"""
		self.s.setDTR(False)
		time.sleep(0.1)
		self.s.setDTR(True)
