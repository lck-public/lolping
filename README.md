# lolping

 monitor latency to LoL server with ICMP and report to remote server

## Requirements

* Windows XP / Windows Server 2003 and newer
* python >=3.5.3
* pip

## Installation

### Clone repo

```powershell
PS C:\> git clone https://github.com/lck-public/lolping.git
```

### Install required python packages

```powershell
PS C:\lolping> pip install -r requirements.txt
```

### Usage

```powershell
PS C:\lolping> python .\lolping.py -h
usage: lolping.py [-h] [-d] [-w TIMEOUT] [-l SIZE] [-i INTERVAL]
                  [-p POST_INTERVAL] [-u URL] [-a AUTH]
                  address

Latency Monitoring with ICMP and Remote Reporting Tool

positional arguments:
  address               specifies the host name or IP address of the
                        destination

optional arguments:
  -h, --help            show this help message and exit
  -d, --debug           enable debug mode (default: False)
  -w TIMEOUT            timeout in milliseconds to wait for each reply
                        (default: 1000)
  -l SIZE               number of data bytes to be sent (default: 32)
  -i INTERVAL           specifies interval between ping packets (default: 1)
  -p POST_INTERVAL      specifies interval between data posting (default: 10)
  -u URL, --url URL     specifies url for result posting (default: None)
  -a AUTH, --auth AUTH  specifies auth token for message posting (default:
                        None)
```

* `lolping.py` posts a message every 10 ICMP requests by default. This can be changed with `-p` option.
* `lolping.py` sends auth key in json formatted message with key 'auth_hash'.

```powershell
PS C:\lolping> python .\lolping.py -d 8.8.8.8
[2020-05-02 22:13:17,390] lolping.py:220 [INFO] Report server url: None
[2020-05-02 22:13:17,393] lolping.py:221 [INFO] Pinging 8.8.8.8 [8.8.8.8] with 32 bytes of data:
[2020-05-02 22:13:17,439] lolping.py:260 [DEBUG] Reply from 8.8.8.8: bytes=32 time=41ms TTL=53
[2020-05-02 22:13:18,483] lolping.py:260 [DEBUG] Reply from 8.8.8.8: bytes=32 time=41ms TTL=53
[2020-05-02 22:13:19,524] lolping.py:260 [DEBUG] Reply from 8.8.8.8: bytes=32 time=38ms TTL=53
[2020-05-02 22:13:20,565] lolping.py:260 [DEBUG] Reply from 8.8.8.8: bytes=32 time=39ms TTL=53
[2020-05-02 22:13:21,607] lolping.py:260 [DEBUG] Reply from 8.8.8.8: bytes=32 time=40ms TTL=53
[2020-05-02 22:13:22,650] lolping.py:260 [DEBUG] Reply from 8.8.8.8: bytes=32 time=40ms TTL=53
[2020-05-02 22:13:22,818] lolping.py:290 [INFO] Ping statistics for 8.8.8.8:
[2020-05-02 22:13:22,820] lolping.py:291 [INFO] Packets: Sent = 6, Received = 6, Lost = 0 (0.00% loss),
[2020-05-02 22:13:22,822] lolping.py:293 [INFO] Approximate round trip times in milli-seconds:
[2020-05-02 22:13:22,840] lolping.py:294 [INFO] Minimum = 38ms, Maximum = 41ms, Average = 39ms Stdev = 1ms
```

Press `CTRL-C` to stop pinging.

## Logging

* All messasges are logged in `lolping.log` file.

## Message

### Format

```json
{
    "requests": 2,
    "responses": 2,
    "loss": 0,
    "rtt_list": [{"timestamp": 1588732000, "rtt": 32}, {"timestamp": 1588732001, "rtt": 31}]
}
```

* requests : number of ICMP request packets sent
* responses : number of ICMP response packets received
* loss : number of unreceived ICMP response packets
* rtt_list : list of RoundTripTime for each ICMP request/response

### Posting

`lolping.py` posts messages with POST method.

```http
POST /api/lolping/rtts?client_hostname=:client_hostname&client_local_ip=:client_local_ip&client_public_ip=:client_public_ip
HOST: https://api.server.com HTTP/1.1
Accept: */*
X-Auth-Hash: JDYkL1FTam50L2o3LlgzVHlKSiRlck94ejZRM1VjQWlZcGxQUVhEVVQyUVlieVBQczVrV28zZVZQakpVY1lZVElGVUZoa0l5LjhzOTZuUjJ4QlBpeDBjdk8udXBqWGl4bHppUGNOQi9lMQ==
Content-type: application/json
{
    "requests": 2,
    "responses": 2,
    "loss": 0,
    "rtt_list": [{"timestamp": 1588732000, "rtt": 32}, {"timestamp": 1588732001, "rtt": 31}]
}
```

## Auth_hash

`auth_hash` is base64 encoded sha512 hash value. (-a AUTH)

```python
from base64 import b64encode
from passlib.hash import sha512_crypt
auth_hash = b64encode(sha512_crypt.hash(AUTH, rounds=5000).encode())
```
