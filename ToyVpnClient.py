#!/usr/bin/python
# coding:utf-8
"""
__version__ = '1.0'
__date__  = '2013-07-29'
__author__ = "shaozheng.wu@gmail.com"
"""

from __future__ import with_statement
import sys
if sys.version_info < (2, 6):
    import simplejson as json
else:
    import json

import os
import hashlib
import getopt
import fcntl
import time
import struct
import socket, select
import traceback
import signal
import logging

#SHARED_PASSWORD = hashlib.sha1("xiaoxia").digest()
TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_NO_PI = 0x1000

TIMEOUT = 60*10 # seconds
DEBUG = 0
BUFFER_SIZE = 32767

class Tunnel():
    def __init__(self):
        self.mParameters = None
        self.tfd = None

    def create(self):
        logging.info("create the interface")
        try:
            self.tfd = os.open("/dev/net/tun", os.O_RDWR)
        except:
            self.tfd = os.open("/dev/tun", os.O_RDWR)
        ifs = fcntl.ioctl(self.tfd, TUNSETIFF, struct.pack("16sH", "tun%d", IFF_TUN|IFF_NO_PI))
        self.tname = ifs[:16].strip("\x00")

    def close(self):
        os.close(self.tfd)

    def config(self, ip):
        logging.info("Configuring interface %s with ip %s" %(self.tname, ip))
        os.system("ip link set %s up" % (self.tname))
        os.system("ip addr add %s dev %s" % (ip, self.tname))
        os.system("ip link set %s mtu %s" % (self.tname,self.mtu))
        os.system("ifconfig %s netmask 255.255.255.0" %self.tname)

    def config_routes(self):
        logging.info("Setting up new gateway ...")
        # Look for default route
        routes = os.popen("ip route show").readlines()
        defaults = [x.rstrip() for x in routes if x.startswith("default")]
        if not defaults:
            raise Exception("Default route not found, maybe not connected!")
        self.prev_gateway = defaults[0]
        self.new_gateway = "default dev %s metric 1" % (self.tname)
        self.tun_gateway = self.prev_gateway.replace("default", SERVER)
        self.old_dns = file("/etc/resolv.conf", "rb").read()
        # Remove default gateway
        os.system("ip route del " + self.prev_gateway)
        # Add route for gateway
        os.system("ip route add " + self.tun_gateway)
        # Add new default gateway
        os.system("ip route add " + self.new_gateway)
        # Set new DNS to 8.8.8.8
        file("/etc/resolv.conf", "wb").write("nameserver %s" %self.dns)

    def restore_routes(self):
        logging.info("Restoring previous gateway ...")
        os.system("ip route del " + self.new_gateway)
        os.system("ip route del " + self.tun_gateway)
        os.system("ip route add " + self.prev_gateway)
        file("/etc/resolv.conf", "wb").write(self.old_dns)

    def handshake(self,tunnel):
        logging.info("handshake with the server ...")
        for i in xrange(3):
            tunnel.sendall(chr(0) + KEY)
            #tunnel.shutdown(1)

        logging.info("start to recv ")
        signal.signal(signal.SIGALRM, onRecvParamTimeout)
        signal.alarm(5)
        packet = tunnel.recv(1024)
        signal.alarm(0)
        logging.info("recv finished == %s" %str(packet).strip())
        if (len(packet) > 0 and packet[0] == chr(0)):
            if 'WRONG PASSWORD' in packet:
                raise Exception("password is wrong") 
            self.configure(str(packet[1:]).strip())
            return
        raise Exception("Failed to login server.")

    def configure(self,parameters):
        logging.info("config the parameters")
        if self.tfd and parameters == self.mParameters:
            logging.info('Using the previous interface')
            return
        for parameter in parameters.split(" "):
            fields = parameter.split(",")
            if   fields[0][0] == 'm':
                self.mtu = int(fields[1])
            elif fields[0][0] == 'a':
                self.address = fields[1]
            elif fields[0][0] == 'd':
                self.dns = fields[1]
        self.mParameters = parameters
        try:
            if self.tfd:
                self.close()
        except:
            logging.error("close interface failed")

        self.create()
        self.config(self.address)
        self.config_routes()

        logging.info("configurate finished...")

    def run(self):
        logging.info("start to run ...")
        self.udpfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udpfd.connect((SERVER, PORT))
        self.handshake(self.udpfd)
        logging.info("connected successful")
        #maxlentfd = 0
        #maxlenudpfd = 0
        aliveTime = time.time()
        while True:
            rset = select.select([self.udpfd, self.tfd], [], [], 1)[0]
            for r in rset:
                if r == self.tfd:
                    if DEBUG: os.write(1,'>')
                    data = os.read(self.tfd, self.mtu)
                    if len(data):
                        self.udpfd.sendall(data)
                        aliveTime = time.time()
                        #print 'the len of data read from interface is %d' %len(data)
                        #maxlentfd = maxlentfd > len(data) and maxlentfd or len(data)
                        #print 'the max lenth of data recv from interface is ',maxlentfd
                elif r == self.udpfd:
                    if DEBUG: os.write(1,'<')
                    data = self.udpfd.recv(BUFFER_SIZE)
                    if data[0] != chr(0):
                        os.write(self.tfd, data)
                    if time.time() - aliveTime > TIMEOUT:
                        logging.info("recieve data from the tunnel timeout")
                        #self.run()

                        #print 'the len of data read from udp tunnel is %d' %len(data)
                        #maxlenudpfd = maxlenudpfd > len(data) and maxlenudpfd or len(data)
                        #print 'the max lenth of data recv from udp tunnel is ',maxlenudpfd



def usage(status = 0):
    print "Usage: %s [-s server|-p port|-k passord|-h help|-d:debug] " % (sys.argv[0])
    sys.exit(status)

def on_exit(no, info):
    raise Exception("TERM or TSTP signal caught!" )

def onRecvParamTimeout(no, info):
    raise Exception("Recieve parameters timeout!" )

if __name__=="__main__":
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)-8s %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S', filemode='a+')

    with open('config.json', 'rb') as f:
        config = json.load(f)
    SERVER = config['server']
    PORT = config['server_port']
    KEY = config['password']

    opts = getopt.getopt(sys.argv[1:],"s:p:k:hd")
    for opt,optarg in opts[0]:
        if opt == "-h":
            usage()
        elif opt == "-s":
            SERVER = socket.gethostbyname(optarg)
        elif opt == "-p":
            PORT = int(optarg)
        elif opt == "-k":
            KEY  = optarg
        elif opt == "-d":
            DEBUG = True

    if False == (SERVER and PORT and KEY):
        usage(1)

    tun = Tunnel()
    signal.signal(signal.SIGTERM, on_exit)
    signal.signal(signal.SIGTSTP, on_exit)
    try:
        tun.run()
    except KeyboardInterrupt:
        pass
    except:
        print traceback.format_exc()
    finally:
        tun.restore_routes()
        tun.close()
