#!/usr/bin/env python3

import sys
import signal
import base64
import socket
from Crypto.Cipher import AES
from Crypto.Hash import SHA512
from Crypto.Random import get_random_bytes
from threading import Timer
from cmd import Cmd
import re

AES256_KEY_LEN = 32
AES_GCM_TAG_LEN = 16
AES_GCM_IV_LEN = 12
CHALLENGE_LEN = 12
CHALLENGE_VALIDITY_TIMEOUT = 60;
SHA_ROUNDS = 5000
KEY_SALT = "FTh.!%B$"

TCP_SERVER_PORT = 4646
UDP_SERVER_PORT = 4647

FLAG_KEEP_ALIVE = "F"
FLAG_BINARY = "B"

class EncryptedMessage:
	
	def __init__(self, rawdata):
		self.rawdata = rawdata
		data = re.findall(r'\[BEGIN\](.*)\[END\]', self.rawdata)[0]
		
		chunks = data.split(":")
		
		self.header = chunks[0]
		self.iv = chunks[1]
		self.tag = chunks[2]
		self.ciphertext = chunks[3]
		
	def decrypt(self, key):
		try:
			iv = base64.b64decode(self.iv)
			tag = base64.b64decode(self.tag)
			ciphertext = base64.b64decode(self.ciphertext)
			cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
			plaintext = cipher.decrypt_and_verify(ciphertext, tag).decode()
			chunks = plaintext.split(":")
			
			flags = chunks[0]
			challenge_response = chunks[1]
			challenge_request = chunks[2]
			if FLAG_BINARY in flags:
				payload = chunks[3]
			else:
				try:
					payload = base64.b64decode(chunks[3]).decode()
				except:
					payload = chunks[3]
			
			return PlaintextMessage(self.header, flags, challenge_response, challenge_request, payload)
		except Exception as x:
			return PlaintextMessage(self.header, "", "", "", self.ciphertext)
		
	def __str__(self):
		return self.rawdata
		
	
class PlaintextMessage:
	
	def __init__(self, header, flags, challenge_response, challenge_request,  payload,):
		self.header = header
		self.flags = flags
		self.payload = payload
		self.challenge_response = challenge_response
		self.challenge_request = challenge_request
		
	def encrypt(self, key):
		iv = get_random_bytes(AES_GCM_IV_LEN)
		cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
		data = f"{self.flags}:{self.challenge_response}:{self.challenge_request}:{base64.b64encode(self.payload.encode()).decode()}".encode()
		ciphertext, tag = cipher.encrypt_and_digest(data)
		
		return EncryptedMessage(f"[BEGIN]{self.header}:{base64.b64encode(iv).decode()}:{base64.b64encode(tag).decode()}:{base64.b64encode(ciphertext).decode()}[END]")
	
	def __str__(self):
		return f"{self.header}:{self.flags}:{self.challenge_response}:{self.challenge_request}:{self.payload}"


class ChallengeManager:
	
	def __init__(self):
		self.challenge_response = ""
	
	def getExpectedChallengeResponse(self):
		return self.challenge_request
	
	def getCurrentChallengeResponse(self):
		return self.challenge_response
		
	def resetChallenge(self):
		self.timer.cancel()
		self.challenge_response = ""
		
	def verifyChallenge(self, challenge_response):
		return self.challenge_request == challenge_response
	
	def rememberChallengeResponse(self, challenge_response):
		self.challenge_response = challenge_response
		self.timer = Timer(CHALLENGE_VALIDITY_TIMEOUT, self.resetChallenge)
		self.timer.daemon = True
		self.timer.start()
	
	def generateChallenge(self):
		self.challenge_request = base64.b64encode(get_random_bytes(CHALLENGE_LEN)).decode()
		return self.challenge_request
	

class Transport_TCP:
	def __init__(self, ip, port):
		self.ip = ip
		self.port = port
	
	def connect(self):
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.sock.connect((self.ip, self.port))
	
	def close(self):
		self.sock.close()
	
	def send(self, data):
		self.sock.send(data)
		if not self.sock:
			self.connect()
		for i in range(3):
			out = self.sock.recv(1024);
			if len(out) > 2:
				return out
		return None
	
class Transport_UDP:
	def __init__(self, ip, port):	
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self.sock.settimeout(2)
		self.ip = ip
		self.port = port

	def connect(self):
		self.sock.connect((self.ip, self.port))
	
	def close(self):
		pass
	
	def send(self, data):
		self.sock.send(data)
		for i in range(3):
			out = self.sock.recv(2048);
			if len(out):
				return out
		return None
	
class CryptCon:
	
	def __init__(self, transport, password):
		h = SHA512.new((password + KEY_SALT).encode())
		for i in range(SHA_ROUNDS):
			h = h.new(h.digest())
		
		self.key = h.digest()[0:32]
		self.transport = transport
		self.chman = ChallengeManager()
	
	def send(self, payload):
		if(self.chman.getCurrentChallengeResponse() == ""):
			message = PlaintextMessage("HELLO", "", "", self.chman.generateChallenge(), "")
			encrypted = message.encrypt(self.key)
			self.transport.connect()
			encrypted_response = EncryptedMessage(self.transport.send(encrypted.rawdata.encode()).decode())
			response = encrypted_response.decrypt(self.key)
			if self.chman.verifyChallenge(response.challenge_response):
				self.chman.rememberChallengeResponse(response.challenge_request)
			else:
				return None
		else:
			self.transport.connect()
		
		message = PlaintextMessage("DATA", "", self.chman.getCurrentChallengeResponse(), self.chman.generateChallenge(), payload)
		encrypted = message.encrypt(self.key)
		encrypted_response = EncryptedMessage(self.transport.send(encrypted.rawdata.encode()).decode())
		response = encrypted_response.decrypt(self.key)
		self.transport.close()
		if self.chman.verifyChallenge(response.challenge_response):
			self.chman.rememberChallengeResponse(response.challenge_request)
			return f"{response.header}:{response.flags}:{response.payload}"
		else:
			if response.payload == "Nope!":
				self.chman.resetChallenge();
				return self.send(payload)
			return f"ERROR: {response.payload}"
		
	def discover():
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
		s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, True)
		s.settimeout(0.2)

		s.sendto("[BEGIN]HELLO:::discover[END]".encode(), ("<broadcast>", UDP_SERVER_PORT))
		devicenames = []
		while True:
			try:
				devicenames.append(s.recvfrom(128))
			except:
				break
			
		devicenames = sorted(devicenames, key=lambda item: item[1][0])
		
		for device in devicenames:
			name = re.findall(r'\[BEGIN\]DATA:::(.*)\[END\]', device[0].decode())[0]
			ip = device[1][0]
			print(f"{name} : {ip}")
			
			
class MyPrompt(Cmd):
	
	def __init__(self, cc):
		self.cc = cc;
		response = self.cc.send("discover").replace("DATA::", "")
		if "ERROR" in response:
			response = ""
		name = response.split(":")[1]
		self.prompt = f"{name}-># "
		super().__init__()
		
	def emptyline(self):
		pass
		
	def do_exit(self, inp):
		return True


	def default(self, inp):
		print(self.cc.send(inp) + "\n");

def exit():
	print()
	quit()

def handler(signum, frame):
	exit()

def main():
	signal.signal(signal.SIGINT, handler)
	CryptCon.discover()
	if len(sys.argv) == 4:
		ip, port = sys.argv[1].split(":")
		password = sys.argv[2]
		payload = sys.argv[3]
		interactive = (payload == "i")
		
		try:
			transport = Transport_UDP(ip, int(port))
			#transport = Transport_TCP(ip, int(port))
		except Exception as x:
			print(F"Connection failed: {x}")
			exit()
		cc = CryptCon(transport, password)

		if interactive:
			prompt = MyPrompt(cc)
			prompt.cmdloop()

		else:
			print(cc.send(payload));
			exit()

if __name__== "__main__":
	main()
