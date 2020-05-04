import argparse
import json
import logging
import logging.config
import os
import socket
import sys
import time
from datetime import datetime
from statistics import stdev

import requests
import winping
from passlib.hash import sha512_crypt
from winping.errors import RequestTimedOut

PUBLIC_IP_LOOKUP=os.getenv("PUBLIC_IP_LOOKUP", "https://ifconfig.co/json")

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
    parser.add_argument("-s", "--server",
                        help="specifies server url to post result",
                        dest="server",
                        default=None)
    parser.add_argument("-a", "--auth",
                        help="specifies auth token for message post",
                        dest="auth",
                        default=None)
    
    args = parser.parse_args()
    return args


def average(lst):
    """Return average value of 'lst'.

    Arguments:
        lst {int, float} -- a list of numbers

    Returns:
        float -- [description]
    """
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
                
        self.local_host = socket.gethostname()
        self.local_ip = socket.getaddrinfo(self.local_host, 0, socket.AF_INET)[0][4][0]
        self.local_public_ip = self._lookup_public_ip()
        
        self.server = args.server
        if args.auth:
            self.auth_hash = self._make_hash(self.local_ip+self.local_public_ip, self.auth)
        else:
            self.auth_hash = None

        self._ping_count = 0
        self._requests = 0
        self._responses = 0
        self._loss = 0
        self._rtt_list = []
        
        self._total_requests = 0
        self._total_responses = 0
        self._total_loss = 0
        self._total_rtt_list = []
        
        self.content = dict(
            server = self.server,
            auth_hash = self.auth_hash,
            local_host = self.local_host,
            local_ip = self.local_ip,
            local_public_ip = self.local_public_ip,
            target_host = self.target_host,
            target_ip = self.target_ip
        )

        lolping_logger.info(f"Report server url: {self.server}")
        lolping_logger.info(f"Auth enabled: {self.auth_hash is not None}")
        lolping_logger.info(f"Pinging {self.target_host} [{self.target_ip}] with {len(self.data)} bytes of data:")

    def __repr__(self):
        return f"{type(self).__name__}({self.content})"

    def _timestamp(self):
        """Return current UNIX timestamp.

        Returns:
            int -- current UNIX timestamp
        """
        return int(datetime.timestamp(datetime.now()))

    def _make_hash(self, salt, auth):
        """Make sha512 hash value with salt and auth.

        Arguments:
            salt {str} -- string for salt
            auth {str} -- string for auth

        Returns:
            str -- sha512 hash value
        """
        return sha512_crypt.hash(salt+auth, rounds=5000)

    def _lookup_public_ip(self):
        """Lookup public IP of local host.

        Returns:
            str -- public ip or 'not found'
        """
        try:
            return requests.get(PUBLIC_IP_LOOKUP).json()['ip']
        except (json.JSONDecodeError, KeyError):
            return 'not found'

    def ping(self, handle):
        while True:
            try:
                self._ping_count += 1
                timestamp_ = self._timestamp()
                res = winping.ping(handle, self.target_ip, timeout=self.timeout, data=self.data)
            except RequestTimedOut:
                self._requests += 1
                self._total_requests += 1
                self._loss += 1
                self._total_loss += 1
            except OSError as e:
                lolping_logger.error(e)
            else:
                self._requests += 1
                self._total_requests += 1
                for rep in res:
                    if rep.Status == 0:
                        rtt = rep.RoundTripTime
                        self._rtt_list.append((timestamp_, rtt))
                        self._total_rtt_list.append((timestamp_, rtt))
                        lolping_logger.debug(f"Reply from {rep.Address}: bytes={len(rep.Data)} time={rtt}ms TTL={rep.Options.Ttl}")
                        if rep.Data != self.data:
                            lolping_logger.error("Corrupted packet!")
                        self._responses += 1
                        self._total_responses += 1
                    else:
                        self._loss += 1
                        self._total_loss += 1
            if self._ping_count % self.post_interval == 0:
                (self._requests, self._responses, self_loss, self._rtt_list) = self._post_rtt_list(self._requests, self._responses, self._loss, self._rtt_list)
            time.sleep(self.interval)

    def _post_rtt_list(self, req_count, resp_count, loss_count, rtt_list):
        data = dict(
            requests = req_count,
            responses = resp_count,
            loss = loss_count,
            rtt_list = rtt_list
        )
        if self.server:
            try:
                url = f"{self.server}/local_host/{self.local_host}/local_ip/{self.local_ip}/local_public_ip/{self.local_public_ip}"

                if self.auth_hash:
                    params = dict(auth_hash = self.auth_hash)
                else:
                    params = None
                r = requests.post(url, params=params, json=data)
                if r.status_code == 200:
                    lolping_logger.info(f"{r.status_code} {r.text}")
                else:
                    lolping_logger.error(f"{r.status_code} {r.text}")
            except json.JSONDecodeError:
                lolping_logger.error(f"invalid rtt_list format: {data}")
            except requests.ConnectionError:
                lolping_logger.error(f"connection failed: {self.server}")
            finally:
                return (0, 0, 0, [])
        else:
            lolping_logger.debug(f"data: {data} server: {self.server} auth_hash: {self.auth_hash}")
            return (req_count, resp_count, loss_count, rtt_list)

    def post_rtt(self, rtt):
        pass

    def statistics(self):
        return dict(
            target_host = self.target_host,
            target_ip = self.target_ip,
            total_requests = self._total_requests,
            total_responses = self._total_responses,
            total_loss = self._total_loss,
            loss_percentage = 100*self._total_loss/self._total_requests,
            max_rtt = max([rtt[1] for rtt in self._total_rtt_list]),
            min_rtt = min([rtt[1] for rtt in self._total_rtt_list]),
            average_rtt = int(average([rtt[1] for rtt in self._total_rtt_list])) if len(self._total_rtt_list) >= 1 else 0,
            stdev_rtt = int(stdev([rtt[1] for rtt in self._total_rtt_list])) if len(self._total_rtt_list) >= 2 else 0
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

    stats = lolping.statistics()
    lolping_logger.info(f"Ping statistics for {stats['target_host']} ({stats['target_ip']}):")
    lolping_logger.info(f"Packets: Sent = {stats['total_requests']}, Received = {stats['total_responses']}, Lost = {stats['total_loss']} ({stats['loss_percentage']:.2f}% loss),")
    lolping_logger.info("Approximate round trip times in milli-seconds:")
    lolping_logger.info(f"Minimum = {stats['min_rtt']}ms, Maximum = {stats['max_rtt']}ms, Average = {stats['average_rtt']}ms Stdev = {stats['stdev_rtt']}ms")

if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        lolping_logger.critical(e)
        sys.exit(1)