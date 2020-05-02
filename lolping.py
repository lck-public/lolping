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
from passlib.hash import sha512_crypt
from winping import *
from winping.errors import *

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


def timestamp():
    """Return current UNIX timestamp.

    Returns:
        int -- current UNIX timestamp
    """
    return int(datetime.timestamp(datetime.now()))


def make_hash(salt, auth):
    """Make sha512 hash value with salt and auth.

    Arguments:
        salt {str} -- string for salt
        auth {str} -- string for auth

    Returns:
        str -- sha512 hash value
    """
    return sha512_crypt.hash(salt+auth, rounds=5000)


def post_message(message, server, auth_hash = None):
    """Post 'message to remote 'server' with 'auth_hash'(optional).

    Arguments:
        message {dict} -- message to post
        server {str} -- remote server url

    Keyword Arguments:
        auth_hash {str} -- sha512 hashed auth key (default: {None})
    """
    

    if server:
        try:
            r = requests.post(server, json=json.dumps(message))
            if r.status_code == 200:
                lolping_logger.info(f"{r.status_code} {r.text}")
            else:
                lolping_logger.error(f"{r.status_code} {r.text}")
        except json.JSONDecodeError:
            lolping_logger.error(f"invalid message format: {message}")
        except requests.ConnectionError:
            lolping_logger.error(f"connection failed: {server}")
    else:
        lolping_logger.debug(f"message: {message} server: {server} auth_hash: {auth_hash}")


def lookup_public_ip():
    """Lookup public IP of local host.

    Returns:
        str -- public ip or 'not found'
    """
    try:
        return requests.get(PUBLIC_IP_LOOKUP).json()['ip']
    except (json.JSONDecodeError, KeyError):
        return 'not found'


def main():
    args = parse_args()
    if args.debug:
        for handler in lolping_logger.handlers:
            if handler.name == 'console':
                handler.setLevel(logging.DEBUG)
    try:
        ai_list = socket.getaddrinfo(args.address, 0, socket.AF_INET)
    except (socket.gaierror, ValueError):
        lolping_logger.error(f"Ping request could not find host '{args.address}'. "
            "Please check the name and try again.")
        sys.exit(3)
    ip = ai_list[0][4][0]
    data = os.urandom(args.size)
    interval = args.interval
    post_interval = args.post_interval
    server = args.server
    auth = args.auth
    
    remote_host = args.address
    local_host = socket.gethostname()
    local_ip = socket.getaddrinfo(local_host, 0, socket.AF_INET)[0][4][0]
    local_public_ip = lookup_public_ip()
    if auth:
        auth_hash = make_hash(local_ip+local_public_ip, auth)
    else:
        auth_hash = None

    lolping_logger.info(f"Report server url: {server}")
    lolping_logger.info(f"Pinging {args.address} [{ip}] with {len(data)} bytes of data:")

    count = 0
    reqs = 0
    resps = 0
    lost = 0
    rtt_list = list()
    
    reqs_total = 0
    resps_total = 0
    lost_total = 0
    rtt_list_total = list()
    min_rtt = float("+inf")
    max_rtt = float("-inf")

    try:
        with IcmpHandle() as handle:
            while True:
                count += 1
                try:
                    timestamp_ = timestamp()
                    res = ping(handle, ip, timeout=args.timeout, data=data)
                except RequestTimedOut:
                    reqs += 1
                    lost += 1
                    reqs_total += 1
                    lost_total += 1
                except OSError as e:
                    lolping_logger.error(e)
                else:
                    reqs += 1
                    reqs_total += 1
                    for rep in res:
                        if rep.Status == 0:
                            rtt = rep.RoundTripTime
                            max_rtt = max(max_rtt, rtt)
                            min_rtt = min(min_rtt, rtt)
                            rtt_list.append((timestamp_, rtt))
                            rtt_list_total.append((timestamp_, rtt))
                            lolping_logger.debug(f"Reply from {rep.Address}: bytes={len(rep.Data)} time={rtt}ms TTL={rep.Options.Ttl}")
                            if rep.Data != data:
                                lolping_logger.error("Corrupted packet!")
                            resps += 1
                            resps_total += 1
                        else:
                            lost += 1
                            lost_total += 1
                            
                if count % post_interval == 0:
                    post_message(dict(
                                    local_host=local_host,
                                    local_ip=local_ip,
                                    remote_host=remote_host,
                                    remote_ip=rep.Address,
                                    requests=reqs,
                                    responses=resps,
                                    rtt_list=rtt_list,
                                    loss=lost), server, auth_hash)
                    reqs = 0
                    resps = 0
                    lost = 0
                    rtt_list = list()
                time.sleep(interval)
    except KeyboardInterrupt:
        pass

    average_rtt = int(average([rtt[1] for rtt in rtt_list_total])) if len(rtt_list_total) > 0 else 0
    stdev_rtt = int(stdev([rtt[1] for rtt in rtt_list_total])) if len(rtt_list_total) > 1 else 0
    if reqs_total:
        lolping_logger.info(f"Ping statistics for {ip}:")
        lolping_logger.info(f"Packets: Sent = {reqs_total}, Received = {resps_total}, Lost = {lost_total} ({(100*lost/reqs_total):.2f}% loss),")
    if resps_total:
        lolping_logger.info("Approximate round trip times in milli-seconds:")
        lolping_logger.info(f"Minimum = {min_rtt}ms, Maximum = {max_rtt}ms, Average = {average_rtt}ms Stdev = {stdev_rtt}ms")

if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        lolping_logger.critical(e)
        sys.exit(1)