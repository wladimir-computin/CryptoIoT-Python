# CryptoIoT-Python
Hubless smarthome OS with E2E-encrypted communication

Serverless smarthome OS with E2E-encrypted communication. Repo for Python Client. 

## Dependencies
```bash
pip3 install -r requirements.txt
``` 

## Usage

### Defaults:

Default local IP in AP-Mode: `192.168.4.1`
Default Password: `TestTest1`

### Scan for CryptioIoT devices:
```bash
./ciot_client2.py

CryptoGarage:CryptoGarage:ECFABC5EF891 : 192.168.178.210
CryptoDimmer:Spots-Einfahrt:C8C9A30E283E : 192.168.178.211
PlugSwitch:PlugSwitch-Flur:807D3A680158 : 192.168.178.212
CryptoDimmer:Licht-Ku:2CF432059130 : 192.168.178.213
[...]
```

### Interactive shell
```bash
./ciot_client2.py <hostname>[:port] <password>

DeviceName->#
```

### Run single command
```bash
./ciot_client2.py <hostname>[:port] <password> status

D::Hostname: DeviceName
System-Version: 10.0c
App-Version: 7.0
Ratelimit: 200ms
Challenge timeout: 60s
Updatemode: 0
Free Heap: 40448Byte
Heap Fragmentation: 1%
Uptime: 9:06:17:41
[...]
```

### Get help
```bash
DeviceName-># help

[...]
```

You can also use tab completion!

