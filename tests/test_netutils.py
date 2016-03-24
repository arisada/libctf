#!/usr/bin/env python3
import unittest
import threading

from libctf import *


class TestTextSocket(unittest.TestCase):
	ready = threading.Event()
	thread = None

	def setUp(self):
		self.ready.clear()
		self.thread = threading.Thread(target=self.textserver, args=())
		self.thread.start()
		self.ready.wait()

	def tearDown(self):
		self.thread.join()
		del self.thread
		self.ready.clear()

	def textserver(self):
		try:
			bindsocket=BindSocket(port=4444)
		except:
			self.ready.set()
			bindsocket.close()
			return
		self.ready.set()
		s = bindsocket.accept(timeout=1.0)
		s.send(b"Hello\n")
		s.send(b"How is it going?\r\n")
		s.send(b"finishedTERMINATOR")
		s.readline(timeout=1)
		s.close()
		bindsocket.close()

	def test_lines(self):
		s = Socket("localhost", 4444)
		s.connect()
		txt = s.readline()
		self.assertEqual(txt, b"Hello")
		txt = s.readline(b"\r\n")
		self.assertEqual(txt, b"How is it going?")
		txt = s.readline(b"TERMINATOR")
		self.assertEqual(txt, b"finished")
		s.send("Finished\n")
		txt = s.readline()
		self.assertEqual(txt, None)
		s.close()

	def test_len(self):
		s = Socket("localhost",4444)
		s.connect()
		txt = s.read_block(len("Hello\n"))
		self.assertEqual(txt, b"Hello\n")
		txt = s.read_block(len("How is it going?\r\n"))
		self.assertEqual(txt, b"How is it going?\r\n")
		s.send("Finished\n")
		s.close()

	def test_poll(self):
		s = Socket("localhost",4444)
		s.connect()
		(r,w,x) = s.poll(read=True, exception=True, timeout=1.0)
		self.assertEqual((r,w,x), (True, False, False))
		# Now socket should have data to read and clear to send
		(r,w,x) = s.poll(read=True, write=True, exception = True, timeout=0.0)
		self.assertEqual((r,w,x), (True, True, False))
		s.readline()
		s.readline()
		s.readline(b"TERMINATOR")
		# now socket should be empty
		(r,w,x) = s.poll(read=True, write=True, exception = True, timeout=0.0)
		self.assertEqual((r,w,x), (False, True, False))
		s.send("Finished\n")
		s.close()
	def test_timeout(self):
		s = Socket("localhost",4444)
		s.connect()
		self.assertRaises(TimeoutException, s.read_block, 1000, 0.2)
		s.close()

class TestBindSocket(unittest.TestCase):
	def test_timeout(self):
		s= BindSocket("::",4444)
		self.assertRaises(TimeoutException, s.accept, 0.2)
		s.close()

if __name__ == '__main__':
	unittest.main()
