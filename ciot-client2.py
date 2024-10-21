#!/usr/bin/env python3

import sys
import signal
import base64
import socket
import serial
import time
import io
from Crypto.Cipher import AES
from Crypto.Hash import SHA512
from Crypto.Random import get_random_bytes
from threading import Timer
from cmd import Cmd
import re
import json

ENCRYPTED_CIOTv2_MESSAGE = "CIOTv2:::"

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
FLAGS_LEN = 5

DEFAULT_LOCAL_IP = "192.168.4.1"

		
class EncryptedMessage:
	
	def __init__(self, rawdata):
		self.rawdata = rawdata
		self.data = re.findall(r'\[BEGIN\](.*)\[END\]', self.rawdata)[0]
		if self.data.startswith(ENCRYPTED_CIOTv2_MESSAGE):
			self.data = self.data.replace(ENCRYPTED_CIOTv2_MESSAGE, "")
			packet = io.BytesIO(base64.b64decode(self.data))
			self.iv = packet.read(AES_GCM_IV_LEN)
			self.tag = packet.read(AES_GCM_TAG_LEN)
			self.ciphertext = packet.read()
		else:
			raise Exception
		
	def decrypt(self, key):
		#try:
		cipher = AES.new(key, AES.MODE_GCM, nonce=self.iv)
		plaintext = cipher.decrypt_and_verify(self.ciphertext, self.tag)
		packet = io.BytesIO(plaintext)
		self.header = packet.read(1).decode()
		if packet.read(1).decode() != ":":
			raise Exception
		flags = packet.read(FLAGS_LEN).decode()
		if packet.read(1).decode() != ":":
			raise Exception
		challenge_response = packet.read(CHALLENGE_LEN)
		challenge_request = packet.read(CHALLENGE_LEN)
		if FLAG_BINARY in flags:
			payload = packet.read()
		else:
			try:
				payload = packet.read().decode()
			except:
				payload = ""
		
		return PlaintextMessage(self.header, flags, challenge_response, challenge_request, payload)
		#except Exception as x:
			#return PlaintextMessage(self.header, "", "", "", self.ciphertext)
		
	def __str__(self):
		return self.rawdata
		

class PlaintextMessage:
	
	def __init__(self, header, flags, challenge_response, challenge_request,  payload):
		self.header = header
		self.payload = payload

		if challenge_response == None:
			challenge_response = bytes(CHALLENGE_LEN)
		self.flags = flags
		self.challenge_response = challenge_response
		self.challenge_request = challenge_request
		
	def encrypt(self, key):
		iv = get_random_bytes(AES_GCM_IV_LEN)
		cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
		if self.flags != None:
			fl = bytes(self.flags.encode())
			fl += b"\0"*(FLAGS_LEN - len(self.flags))
		else:
			fl = bytes(5)
		data = bytes()
		data += self.header.encode() + b":" + fl + b":" + self.challenge_response + self.challenge_request + self.payload.encode()
		ciphertext, tag = cipher.encrypt_and_digest(data)
		
		return EncryptedMessage(f"[BEGIN]{ENCRYPTED_CIOTv2_MESSAGE}{base64.b64encode(iv+tag+ciphertext).decode()}[END]")
	
	def __str__(self):
		return f"{self.header}:{self.flags}:{self.challenge_response}:{self.challenge_request}:{self.payload}"


class ChallengeManager:
	
	def __init__(self):
		self.challenge_response = bytes(CHALLENGE_LEN)
	
	def getExpectedChallengeResponse(self):
		return self.challenge_request
	
	def getCurrentChallengeResponse(self):
		return self.challenge_response
		
	def resetChallenge(self):
		self.timer.cancel()
		self.challenge_response = bytes(CHALLENGE_LEN)
		
	def verifyChallenge(self, challenge_response):
		return self.challenge_request == challenge_response
	
	def rememberChallengeResponse(self, challenge_response):
		self.challenge_response = challenge_response
		self.timer = Timer(CHALLENGE_VALIDITY_TIMEOUT, self.resetChallenge)
		self.timer.daemon = True
		self.timer.start()
	
	def generateChallenge(self):
		self.challenge_request = get_random_bytes(CHALLENGE_LEN)
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
	
class Transport_SERIAL:
	ser = None
	def __init__(self, device="/dev/ttyUSB0", baud=115200):	
		self.ser = serial.Serial(device, baudrate=baud, timeout=None)
		
	def connect(self):
		pass
	
	def close(self):
		self.ser.close()
	
	def send(self, data):
		self.ser.write(data.encode("UTF-8") + b"\n")
		self.ser.flush()
		time.sleep(0.1)
		self.ser.read(len(data.encode("UTF-8"))+2)
		out = b""
		while self.ser.in_waiting > 0:
			out += self.ser.read(self.ser.in_waiting)
		try:
			return out.decode("UTF-8")[0:-1]
		except:
			return ""
	
class PlainCon:
	def __init__(self, transport):
		self.transport = transport
		
	def send(self, payload):
		return self.transport.send(payload)
	
	
class CryptCon:
	
	def __init__(self, transport, password):
		h = SHA512.new((password + KEY_SALT).encode())
		for i in range(SHA_ROUNDS):
			h = h.new(h.digest())
		
		self.key = h.digest()[0:32]
		self.transport = transport
		self.chman = ChallengeManager()
	
	def send(self, payload):
		if self.chman.getCurrentChallengeResponse() == bytes(CHALLENGE_LEN):
			message = PlaintextMessage("H", None, None, self.chman.generateChallenge(), "")
			encrypted = message.encrypt(self.key)
			self.transport.connect()
			try:
				encrypted_response = EncryptedMessage(self.transport.send(encrypted.rawdata.encode()).decode())
			except:
				print("Communication failed, wrong password?")
				return
			response = encrypted_response.decrypt(self.key)
			if self.chman.verifyChallenge(response.challenge_response):
				self.chman.rememberChallengeResponse(response.challenge_request)
			else:
				return None
		else:
			self.transport.connect()
		
		message = PlaintextMessage("D", None, self.chman.getCurrentChallengeResponse(), self.chman.generateChallenge(), payload)
		encrypted = message.encrypt(self.key)
		response = self.transport.send(encrypted.rawdata.encode()).decode()
		if "ERROR" not in response:
			encrypted_response = EncryptedMessage(response)
			response = encrypted_response.decrypt(self.key)
			if response.header != "H":
				response.flags = response.flags.replace("\0", "")
				self.transport.close()
				if self.chman.verifyChallenge(response.challenge_response):
					self.chman.rememberChallengeResponse(response.challenge_request)
					return f"{response.header}:{response.flags}:{response.payload}"
				else:
					if response.payload == "Nope!":
						self.chman.resetChallenge();
						return self.send(payload)
					return f"ERROR: {response.payload}"
			else:
				if self.chman.verifyChallenge(response.challenge_response):
					self.chman.rememberChallengeResponse(response.challenge_request)
					self.send(payload)
				else:
					return None
		else:
			self.chman.resetChallenge();
			return re.findall(r'\[BEGIN\](.*)\[END\]', response)[0]
		
	def discover():
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
		s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, True)
		s.settimeout(0.2)

		s.sendto("[BEGIN]CIOTv2:::discover[END]".encode(), ("<broadcast>", UDP_SERVER_PORT))
		devicenames = []
		while True:
			try:
				devicenames.append(s.recvfrom(128))
			except:
				break
			
		devicenames = sorted(devicenames, key=lambda item: item[1][0])
		for device in devicenames:
			try:
				name = re.findall(r'\[BEGIN\]CIOTv2:::(.*)\[END\]', device[0].decode())[0]
				ip = device[1][0]
				print(f"{name} : {ip}")
			except:
				pass
			
class MyPrompt(Cmd):
	
	def __init__(self, cc):
		self.cc = cc
		self.api = {}
		self.apps = {}
		try:
			response = self.cc.send("discover")
			if response is not None:
				response = response.replace("\0\0\0\0\0", "")
				response = response.replace("D::", "")
				api_temp = json.loads(self.cc.send("api").replace("D::", ""))
				for cmd_obj in api_temp:
					key = list(cmd_obj.keys())[0]
					self.api[key] = cmd_obj[key]
				api_temp = json.loads(self.cc.send("apps").replace("D::", ""))
				for app_obj in api_temp:
					key = list(app_obj.keys())[0]
					self.apps[key] = app_obj[key]
					
					app_api = json.loads(self.cc.send(F"api:{key}").replace("D::", ""))
					self.api[key] = {}
					for app_api_obj in app_api:
						app_api_key = list(app_api_obj.keys())[0]
						self.api[key][app_api_key] = app_api_obj[app_api_key]
				if "ERROR" in response:
					response = ""
				name = response.split(":")[1]
				self.prompt = f"{name}-># "
				super().__init__()
			else:
				print("Exiting!")
				exit()
				
		except Exception as x:
			raise x
			exit()
		
	def emptyline(self):
		pass
		
	def do_exit(self, inp):
		return True
	
	def complete_reads(self, text, line, begidx, endidx):
		commands = line.split(":")
		
		if len(commands) == 2:
			response = self.cc.send("reads")
			response = response.rstrip().replace("D:F:", "")
			if "ERROR" not in response:
				completes = [vault for vault in response.split("\n") if vault.lower().startswith(text.lower())]
				if not (len(completes) == 1 and completes[0] == text):
					return completes
				else:
					return [F"{completes[0]}:"]
		
		if len(commands) == 3:
			response = self.cc.send("reads:" + commands[1]).replace("D:F:", "")
			if "ERROR" not in response:
				keys = json.loads(response).keys()
				completes = [key for key in keys if key.lower().startswith(text.lower())]
				if not (len(completes) == 1 and completes[0] == text):
					return completes
				else:
					if commands[0] == "writes":
						return [F"{completes[0]}:"]
		
		return []
		
	def complete_writes(self, text, line, begidx, endidx):
		commands = line.split(":")
		
		if len(commands) == 4:
			if commands[3] == "":
				response = self.cc.send("reads:" + commands[1] + ":" + commands[2]).replace("D:F:", "")
				if "ERROR" not in response:
					return [response]
		else:
			return self.complete_reads(text, line, begidx, endidx)
		
	def complete_reset(self, text, line, begidx, endidx):
		return self.complete_reads(text,line,begidx,endidx)
		
	def complete_api(self, text, line, begidx, endidx):
		commands = line.split(":")
		
		if len(commands) == 2:
			return [app for app in self.apps.keys() if app.startswith(commands[1])]

	def default(self, inp):
		print(self.cc.send(inp) + "\n");
		
	def completedefault(self, text, line, begidx, endidx):
		commands = line.split(":")
		# Context is an App, completing command:
		if len(commands) == 2 and commands[0] in self.apps:
			completes = [cmd for cmd in self.api[commands[0]].keys() if cmd.startswith(commands[1])]
			if not (len(completes) == 1 and completes[0] == text):
				return completes
			else:
				if len(self.api[commands[0]][commands[1]]) > 0:
					return [F"{completes[0]}:"]
		# Context is an App with given command, completing paramaters
		elif len(commands) >= 3 and commands[0] in self.apps:
			if commands[len(commands)-1] == "":
				param = list(self.api[commands[0]][commands[1]].keys())[len(commands)-3]
				value = self.api[commands[0]][commands[1]][param]
				type = value["type"]
				optional = '?' if 'optional' in value and value["optional"] else ''
				return [F"{optional}[{param}|{type}]"]
			else:
				if len(list(self.api[commands[0]][commands[1]].keys())) >= len(commands)-1:
					return [":"]
		# Context is a system command, completing paramaters
		elif len(commands) >= 2:
			if commands[len(commands)-1] == "":
				param = list(self.api[commands[0]].keys())[len(commands)-2]
				value = self.api[commands[0]][param]
				type = value["type"]
				optional = '?' if 'optional' in value and value["optional"] else ''
				return [F"{optional}[{param}|{type}]"]
			else:
				if len(list(self.api[commands[0]].keys())) >= len(commands):
					return [":"]
		return []
		
	def completenames(self, text, *a):
		commands = text.split(":")
		if len(commands) == 1:
			completes = [cmd for cmd in self.api.keys() if cmd.startswith(text)]
			if not (len(completes) == 1 and completes[0] == text):
				return completes
			else:
				if len(self.api[commands[0]]) > 0:
					return [F"{completes[0]}:"]

def exit():
	print()
	quit()

def handler(signum, frame):
	exit()

def main():
	signal.signal(signal.SIGINT, handler)
	cc = None
	if len(sys.argv) >= 3:
		if ":" in sys.argv[1] or not sys.argv[1].startswith("/"):
			ip = DEFAULT_LOCAL_IP
			port = UDP_SERVER_PORT
			if ":" in sys.argv[1]:
				ip = sys.argv[1].split(":")[0]
				port = int(sys.argv[1].split(":")[1])
			else:
				ip = sys.argv[1]
			password = sys.argv[2]
			
			try:
				transport = Transport_UDP(ip, port)
				#transport = Transport_TCP(ip, int(port))
			except Exception as x:
				print(F"Connection failed: {x}")
				exit()
			cc = CryptCon(transport, password)

		else:
			device = sys.argv[1]
			baud = sys.argv[2]
			payload = sys.argv[3]
			
			try:
				transport = Transport_SERIAL(device, baud)
			except Exception as x:
				print(F"Connection failed: {x}")
				exit()
			cc = PlainCon(transport)
			
		if len(sys.argv) == 4:
			payload = sys.argv[3]
			interactive = (payload == "i")
		else:
			interactive = True

		if interactive:
			prompt = MyPrompt(cc)
			prompt.cmdloop()
		else:
			print(cc.send(payload));
			exit()
	else:
		CryptCon.discover()
		print()

if __name__== "__main__":
	main()
