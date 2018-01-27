#!/usr/bin/env python3

import argparse

from libctf import Serial

def main():
	parser = argparse.ArgumentParser(description="Open a tty console")
	parser.add_argument('device', nargs="?", help='serial device', metavar="device")
	parser.add_argument('-b', help='9600/19200/38400/57600/115200 (*)', type=int, nargs=1, metavar="baud_rate")
	parser.add_argument('-r', action="store_true", help='Reset at startup (DTR)')

	args = parser.parse_args()
	device = None
	if args.device:
		device = args.device
	baud_rate = 115200
	if args.b:
		baud_rate = args.b
	s = Serial(device=device, baudrate=baud_rate, reset_on_open=args.r)
	if not args.device:
		print("Connected to", s.device)
	s.interactConsole()

if __name__ == '__main__':
	main()
