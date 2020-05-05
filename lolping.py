import argparse
import json
import logging
import logging.config
import os
import socket
import sys
import time
from base64 import b64encode
from datetime import datetime
from statistics import stdev

import requests
import winping
from passlib.hash import sha512_crypt
from winping.errors import RequestTimedOut

logging.config.dictConfig({
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'simple': {
            'format': '[%(asctime)s] %(filename)s:%(lineno)d [%(levelname)s] %(message)s'
        }
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'simple',
            'level': 'INFO',
            'stream': 'ext://sys.stdout'
        },
        'logfile': {
            'backupCount': 10,
            'class': 'logging.handlers.RotatingFileHandler',
            'encoding': 'utf8',
            'filename': 'lolping.log',
            'formatter': 'simple',
            'level': 'DEBUG',
            'maxBytes': 10485760
        }
    },
    'loggers': {
        'lolping': {
            'handlers': ['console', 'logfile'],
            'level': 'DEBUG'
        }
    }
})
lolping_logger = logging.getLogger('lolping')

def parse_args():
    def check_positive_int(value):
        value = int(value)
        if value <= 0:
             raise argparse.ArgumentTypeError(
                 "%s is an invalid positive number value" % value)
        return value

    def check_nonnegative_int(value):
        value = int(value)
        if value < 0:
             raise argparse.ArgumentTypeError(
                 "%s is an invalid non-negative number value" % value)
        return value

    def check_size(value):
        value = int(value)
        if not (0 <= value <= 65500):
             raise argparse.ArgumentTypeError(
                 "Bad data size, valid range is from 0 to 65500)")
        return value

    parser = argparse.ArgumentParser(
        description="Ping implementation which utilizes Windows ICMP API",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("address",
                        help="specifies the host name or IP address of the "
                        "destination")
    parser.add_argument("-d", "--debug",
                        help="enable debug mode",
                        dest="debug",
                        action="store_true",
                        default=False)
    parser.add_argument("-w",
                        help="timeout in milliseconds to wait for each reply",
                        type=check_positive_int,
                        dest="timeout",
                        default=1000)
    parser.add_argument("-l",
                        help="number of data bytes to be sent",
                        type=check_size,
                        dest="size",
                        default=32)
    parser.add_argument("-i",
                        help="specifies interval between ping packets",
                        type=check_positive_int,
                        dest="interval",                        
                        default=1)
    parser.add_argument("-p",
                        help="specifies interval between data posting",
                        type=check_positive_int,
                        dest="post_interval",                        
                        default=10)
    parser.add_argument("-u", "--url",
                        help="specifies url for result posting",
                        dest="url",
                        default=None)
    parser.add_argument("-a", "--auth",
                        help="specifies auth token for message posting",
                        dest="auth",
                        default=None)
    
    args = parser.parse_args()
    return args


def average(lst):
    return round(sum(lst) / len(lst), 3)


class LolPing:
    def __init__(self, args):
        self.data = os.urandom(args.size)
        self.interval = args.interval
        self.post_interval = args.post_interval
        self.timeout = args.timeout

        self.target_host = args.address
        try:
            ai_list = socket.getaddrinfo(args.address, 0, socket.AF_INET)
            self.target_ip = ai_list[0][4][0]
        except (socket.gaierror, ValueError):
            lolping_logger.error(f"Ping request could not find host '{args.address}'. "
                "Please check the name and try again.")
            sys.exit(3)
                
        self.client_hostname = socket.gethostname()
        self.client_local_ip = socket.getaddrinfo(self.client_hostname, 0, socket.AF_INET)[0][4][0]
        self.client_public_ip = self._lookup_public_ip()
        
        self.url = args.url
        self.auth = args.auth
        if self.auth:
            self.auth_hash = self._make_hash(self.auth)
        else:
            self.auth_hash = None
        
        self._total_requests = 0
        self._total_responses = 0
        self._total_loss = 0
        self._total_rtt_list = []
        
        self.content = dict(
            url = self.url,
            auth_hash = self.auth_hash,
            client_hostname = self.client_hostname,
            client_local_ip = self.client_local_ip,
            client_public_ip = self.client_public_ip,
            target_host = self.target_host,
            target_ip = self.target_ip
        )

        lolping_logger.info(f"Report url: {self.url}")
        lolping_logger.info(f"Auth enabled: {self.auth_hash is not None}")
        lolping_logger.info(f"Pinging {self.target_host} [{self.target_ip}] with {len(self.data)} bytes of data:")

    def __repr__(self):
        return f"{type(self).__name__}({self.content})"

    def _timestamp(self):
        return int(datetime.timestamp(datetime.now()))

    def _make_hash(self, auth):
        return b64encode(sha512_crypt.hash(auth, rounds=5000).encode())

    def _lookup_public_ip(self):
        try:
            r = requests.get('https://ifconfig.me')
            if r.status_code == 200:
                return r.text
            else:
                lolping_logger.warning("public ip lookup failed.")
                return 'not found'
        except requests.ConnectionError:
            lolping_logger.warning("public ip lookup failed.")
            return 'not found'

    def ping(self, handle):
        ping_count = 0
        req_count = 0
        resp_count = 0
        loss_count = 0
        rtt_list = []
        while True:
            try:
                ping_count += 1
                timestamp = self._timestamp()
                res = winping.ping(handle, self.target_ip, timeout=self.timeout, data=self.data)
            except RequestTimedOut:
                req_count += 1
                loss_count += 1
                self._total_requests += 1
                self._total_loss += 1
            except OSError as e:
                lolping_logger.error(e)
            else:
                req_count += 1
                self._total_requests += 1
                for rep in res:
                    if rep.Status == 0:
                        rtt = rep.RoundTripTime
                        rtt_list.append(dict(timestamp = timestamp, rtt = rtt))
                        self._total_rtt_list.append(dict(timestamp = timestamp, rtt = rtt))
                        lolping_logger.debug(f"Reply from {rep.Address}: bytes={len(rep.Data)} time={rtt}ms TTL={rep.Options.Ttl}")
                        if rep.Data != self.data:
                            lolping_logger.error("Corrupted packet!")
                        resp_count += 1
                        self._total_responses += 1
                    else:
                        loss_count += 1
                        self._total_loss += 1
            if ping_count % self.post_interval == 0:
                (req_count, resp_count, loss_count, rtt_list) = self._post_rtt_list(req_count, resp_count, loss_count, rtt_list)
            time.sleep(self.interval)

    def _post_rtt_list(self, req_count, resp_count, loss_count, rtt_list):
        data = dict(
            requests = req_count,
            responses = resp_count,
            loss = loss_count,
            rtt_list = rtt_list
        )
        if self.url:
            try:
                params = dict(
                    client_hostname = self.client_hostname,
                    client_local_ip = self.client_local_ip,
                    client_public_ip = self.client_public_ip,
                    auth_hash = self.auth_hash or ''
                )
                r = requests.post(self.url, params=params, json=data, timeout=2)
                lolping_logger.debug(f"request url: {r.url}")
                if r.status_code == 200:
                    lolping_logger.info(f"{r.status_code} {r.text}")
                else:
                    lolping_logger.error(f"{r.status_code} {r.text}")
            except json.JSONDecodeError:
                lolping_logger.error(f"invalid rtt_list format: {data}")
            except requests.ConnectionError:
                lolping_logger.error(f"connection failed: {self.url}")
            except requests.Timeout:
                lolping_logger.error(f"connection timeout: {self.url}")
            finally:
                return (0, 0, 0, [])
        else:
            lolping_logger.debug(json.dumps(data))
            return (0, 0, 0, [])

    def stats(self):
        return dict(
            target_host = self.target_host,
            target_ip = self.target_ip,
            total_requests = self._total_requests,
            total_responses = self._total_responses,
            total_loss = self._total_loss,
            loss_percentage = 100*self._total_loss/self._total_requests,
            max_rtt = max([rtt['rtt'] for rtt in self._total_rtt_list]),
            min_rtt = min([rtt['rtt'] for rtt in self._total_rtt_list]),
            average_rtt = int(average([rtt['rtt'] for rtt in self._total_rtt_list])) if len(self._total_rtt_list) >= 1 else 0,
            stdev_rtt = int(stdev([rtt['rtt'] for rtt in self._total_rtt_list])) if len(self._total_rtt_list) >= 2 else 0
        )

def main():
    args = parse_args()
    if args.debug:
        for handler in lolping_logger.handlers:
            if handler.name == 'console':
                handler.setLevel(logging.DEBUG)

    lolping = LolPing(args)

    try:
        with winping.IcmpHandle() as handle:
            lolping.ping(handle)
    except KeyboardInterrupt:
        pass

    stats = lolping.stats()
    lolping_logger.info(f"Ping statistics for {stats['target_host']} ({stats['target_ip']}):")
    lolping_logger.info(f"Packets: Sent = {stats['total_requests']}, "
                        f"Received = {stats['total_responses']}, "
                        f"Lost = {stats['total_loss']} ({stats['loss_percentage']:.2f}% loss),")
    lolping_logger.info("Approximate round trip times in milli-seconds:")
    lolping_logger.info(f"Minimum = {stats['min_rtt']}ms, Maximum = {stats['max_rtt']}ms, "
                        f"Average = {stats['average_rtt']}ms Stdev = {stats['stdev_rtt']}ms")

if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        lolping_logger.critical(e)
        sys.exit(1)
