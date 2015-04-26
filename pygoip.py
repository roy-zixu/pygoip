#!/usr/bin/env python

import re
import socket
import itertools
import logging

logging.basicConfig(filename='scan.log', level=logging.INFO)


def build_ip_ranges(ipfile):
    ip_ranges = []
    with open(ipfile) as f:
        for line in f:
            if not line.startswith('#'):
                ip_ranges.append(line)
            
    return ip_ranges
    
def clean_range(x):
    '''make a clean range. 
    For example, if x='1' then return 1
    if x='100-200' then return range(100,200)
    '''
    minus = x.find('-')
    if minus < 0:
        return [int(x)]
    first = int(x[:minus])
    last = int(x[minus+1:])
    return range(first, last)
    
def test_socket(addr, port=443, timeout=3.0):
    '''To test if we can connect to the (address, port)'''
    logging.info('testing %s:%d', addr, port)
    result = False
    try:
        sock = socket.socket()
        sock.settimeout(timeout)
        sock.connect((addr, port))
    except socket.timeout,e:
        # logging.info('socket.timeout: %s', e.message)
        pass
    except socket.error,e:
        # logging.info('socket.error: %s', e.message)
        pass
    else:
        logging.info('Got a good IP: %s', addr)
        result = True
    finally:
        sock.close()
    return result
        
def test_http(addr, port=443):
    return True
    
def scan_ip(ip_ranges, maximum=20):
    goods = []
    bads = []
    try:
        for (idx, line) in enumerate(ip_ranges):
            logging.info("testing %d: %s ...", idx, line.strip())
            parts = line.split('.')
            a,b,c,d = list(map(clean_range, parts))
            for ip_group in itertools.product(a,b,c,d):
                ip = '.'.join(map(str, ip_group))
                logging.info("scanning %s", ip)
                # test ip via socket and http
                if test_socket(ip) and test_http(ip):
                    goods.append(ip)
                    print 'good ip: {}'.format(ip)
                    if maximum > 0 and len(goods) >= maximum:
                        break
                else:
                    bads.append(ip)
            if maximum > 0 and len(goods) >= maximum:
                break
    except KeyboardInterrupt:
        pass

    logging.info("scan %d ips: %s", len(goods), goods)
    return goods
    
def begin(maximum=20):
    
    iprange = build_ip_ranges(r'InnerIpSet.txt')
    goods = scan_ip(iprange, maximum)
    print 'Scanned %d IPs:'
    print '|'.join(goods)

if __name__ == '__main__':
    begin()
