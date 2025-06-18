#!/usr/bin/env python3

import sys
import os
from threading import Timer
import re
import json
import argparse
import signal
import base64
import socket
from typing import NamedTuple
import traceback

import time
import io

#pip
from Crypto.Cipher import AES
from Crypto.Hash import SHA512
from Crypto.Random import get_random_bytes
from cmd import Cmd
import serial
from serial.tools.list_ports import comports


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
DEFAULT_SERIAL_BAUD = 115200



class Logger:
    level = 3

    def debug(self, stuff=""):
        if self.level >= 4:
            print(f"[WTF] {stuff}")

    def print(self, stuff=""):
        if self.level >= 3:
            print(stuff)

    def info(self, stuff=""):
        if self.level >= 3:
            print(f"[+] {stuff}")

    def warn(self, stuff=""):
        if self.level >= 2:
            print(f"[-] {stuff}")

    def error(self, stuff=""):
        if self.level >= 1:
            print(f"[!] {stuff}")

log = Logger()


class DiscoveryDevice(NamedTuple):
    devicename : str
    devicetype : str
    deviceid : str
    devicepath : str

    def __str__(self):
        return f"{self.devicepath} : {self.devicetype}:{self.devicename}:{self.deviceid}"

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
    def __init__(self, device, baud):
        self.ser = serial.Serial(device, baudrate=baud, timeout=0.5)

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
        out += self.ser.read(self.ser.in_waiting)
        try:
            return out.decode("UTF-8")[0:-1]
        except:
            return ""

class Discovery:

    def isPrio(device):
        priority_list = ["usbmodem", "ttyUSB", "ttyACM"]

        for pattern in priority_list:
            if pattern in device:
                return True
        return False

    def discoverNetwork() -> list[tuple[str, str]]:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, True)
        s.settimeout(0.2)

        s.sendto("[BEGIN]CIOTv2:::discover[END]".encode(), ("<broadcast>", UDP_SERVER_PORT))
        network_devices = []
        while True:
            try:
                response, addr = s.recvfrom(128)
                ip = addr[0]
                match = re.search(r'\[BEGIN\]CIOTv2:::(.*)\[END\]', response.decode())
                if match:
                    parts = match.group(1)
                    data = parts.split(':')
                    result = DiscoveryDevice(devicename=data[1], devicetype=data[0], deviceid=data[2], devicepath=ip)
                    network_devices.append(result)
            except TimeoutError:
                return network_devices
            except Exception as x:
                log.error(x)

    def discoverSerial(baud=DEFAULT_SERIAL_BAUD):
        serial_devices = []
        for d in comports():
            if Discovery.isPrio(d.device):
                try:
                    transport = Transport_SERIAL(d.device, baud)
                    cc = PlainCon(transport)
                    response = cc.send("discover")
                    cc.transport.close()
                    if response:
                        if response.startswith("D::"):
                            data = response.split(':')
                            result = DiscoveryDevice(devicename=data[3], devicetype=data[2], deviceid=data[4], devicepath=d.device)
                            serial_devices.append(result)
                except Exception as x:
                    log.error(x)
        return serial_devices

    def filterDevice(devices, devicetype):
        if devicetype:
            devices = [d for d in devices if d.devicetype.lower() == devicetype.lower()]
        if devices:
            if len(devices) > 1:
                log.warn(f"Warning, found multiple matching devices:")
                for d in devices:
                    log.print(d)

            d = devices[0]
            log.info(f"Using: {d}")
        return devices[0]

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
                log.error("Communication failed, wrong password?")
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
                log.info("Exiting!")
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

    def do_help(self, *args):
        Cmd.do_help(self, *args)
        print("Available system commands:")
        print("======================    ")
        print(self.cc.send("help").replace("D::", ""))
        print("Available app commands:")
        print("======================")
        for appname in self.apps.keys():
            print(F"\n=== {appname} ===")
            print(self.cc.send(F"help:{appname}").replace("D::", ""))



def exit():
    print()
    quit()

def handler(signum, frame):
    exit()

def main():
    signal.signal(signal.SIGINT, handler)

    parser = argparse.ArgumentParser(description='CryptoIoT Python CLI')

    # Create mutually exclusive group for connection types
    connection_group = parser.add_mutually_exclusive_group(required=False)

    parser.add_argument('--verbosity', '-v', default=3, type=int, help='0 is quiet, 4 is loud')


    # Network connection arguments
    connection_group.add_argument('--network', '-n', metavar='HOST' ,
                                help=f'Network connection (IP or hostname)')
    parser.add_argument('--port', '-p', type=int, default=UDP_SERVER_PORT, help=f'Port for network connection (default: {UDP_SERVER_PORT})')
    parser.add_argument('--password', '-P', type=str, default='TestTest1', help=f'Device password for network connection (default: TestTest1)')

    # Serial connection arguments
    connection_group.add_argument('--serial', '-s', metavar='DEVICE',
                                help='Serial device path (e.g., /dev/ttyUSB0)')
    parser.add_argument('--baud', '-b', type=int, default=DEFAULT_SERIAL_BAUD,
                       help=f'Baud rate for serial connection (default: {DEFAULT_SERIAL_BAUD})')

    # Payload/command arguments
    parser.add_argument('--command', '-c', nargs='*',
                       help='Command(s) to send (ommit for interactive mode)')

    connection_group.add_argument('--autoserial', '-S', nargs='?', default='NOT_SET', metavar='DEVICETYPE', help='Use first serial device matching type (optional)')

    connection_group.add_argument('--autonetwork', '-N', nargs='?', default='NOT_SET', metavar='DEVICETYPE', help='Use first network device matching type (optional)')

    args = parser.parse_args()

    log.level = args.verbosity

    try:
        if args.network or args.autonetwork != "NOT_SET":
            if args.network:
                network = args.network
            else:
                network = Discovery.filterDevice(Discovery.discoverNetwork(), args.autonetwork).devicepath

            if network:
                transport = Transport_UDP(network, args.port)
                #transport = Transport_TCP(ip, int(port))
                cc = CryptCon(transport, args.password)
            else:
                log.error("No CIoT devices found, exiting.")
                sys.exit(1)

        elif args.serial or args.autoserial != "NOT_SET":
            if args.serial:
                serial_device = args.serial
            else:
                serial_device = Discovery.filterDevice(Discovery.discoverSerial(), args.autoserial).devicepath

            if serial_device:
                transport = Transport_SERIAL(serial_device, args.baud)
                cc = PlainCon(transport)
            else:
                log.error("No CIoT devices found, exiting.")
                sys.exit(1)

        else:
            network_devices = Discovery.discoverNetwork()
            if network_devices:
                log.print("=== Network Devices ===")
                for d in network_devices:
                    log.print(d)
                log.print()

            serial_devices = Discovery.discoverSerial()
            if serial_devices:
                log.print("=== Serial Devices ===")
                for d in serial_devices:
                    log.print(d)
                log.print()

            if not network_devices and not serial_devices:
                log.error("No devices found. Use -h for help.\n")
                sys.exit(1)
            return

        if args.command:
            for cmd in args.command:
                print(f"{cmd} -> ", end='')
                print(cc.send(cmd));
        else:
            prompt = MyPrompt(cc)
            prompt.cmdloop()

    except Exception as x:
            log.error(F"Unhandled error: {x}")
            traceback.print_exc()
            sys.exit(1)

if __name__== "__main__":
    main()
