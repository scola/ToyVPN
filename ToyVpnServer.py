#!/usr/bin/python

'''
    UDP Tunnel VPN
    Xiaoxia (xiaoxia@xiaoxia.org)
    Updated: 2012-2-21
'''

import os, sys
import hashlib
import getopt
import fcntl
import time
import struct
import socket, select
import traceback
import signal
import ctypes
import binascii
import logging

SHARED_PASSWORD = hashlib.sha1("xiaoxia").digest()
TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_NO_PI = 0x1000

BUFFER_SIZE = 32767
MODE = 0
DEBUG = 1
PORT = 0
KEY = None
IFACE_IP = "10.0.0.5"
MTU = 1500
TIMEOUT = 60*10 # seconds

class Tunnel():
    def create(self):
        try:
            self.tfd = os.open("/dev/net/tun", os.O_RDWR)
        except:
            self.tfd = os.open("/dev/tun", os.O_RDWR)
        ifs = fcntl.ioctl(self.tfd, TUNSETIFF, struct.pack("16sH", "tun%d", IFF_TUN| IFF_NO_PI))
        self.tname = ifs[:16].strip("\x00")

    def close(self):
        os.close(self.tfd)

    def config(self, ip):
        print "Configuring interface %s with ip %s" % (self.tname, ip)
        os.system("ip link set %s up" % (self.tname))
        #os.system("ip link set %s mtu 1000" % (self.tname))
        os.system("ip addr add %s dev %s" % (ip, self.tname))
        os.system("ifconfig %s netmask 255.255.255.0" %self.tname)
    """
    @staticmethod
    def build_parameters(parameters):
        " ".join(["%s,%s" % (k[0], v) for k, v in params.items()])
    """

    def run(self):
        global PORT
        self.udpfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udpfd.bind(("", PORT))
        self.clients = {}

        while True:
            rset = select.select([self.udpfd, self.tfd], [], [], 1)[0]
            for r in rset:
                if r == self.tfd:
                    if DEBUG: os.write(1, ">")
                    data = os.read(self.tfd, BUFFER_SIZE)
                    dst = data[16:20]
                    #print socket.inet_ntoa(dst)
                    for key in self.clients:
                        if dst == self.clients[key]["localIPn"]:
                            self.udpfd.sendto(data, key)
                    # Remove timeout clients
                    curTime = time.time()
                    for key in self.clients.keys():
                        if curTime - self.clients[key]["aliveTime"] > TIMEOUT:
                            print "Remove timeout client", key
                            del self.clients[key]

                elif r == self.udpfd:
                    if DEBUG: os.write(1, "<")
                    data, src = self.udpfd.recvfrom(BUFFER_SIZE)
                    #print data
                    key = src
                    if key not in self.clients:
                        # New client comes
                        try:
                            if data[0] == chr(0) and data[1:] == KEY:
                                localIP = parameters['address'].split(',')[0]
                                IPchr = socket.inet_aton(localIP)
                                IPchr = struct.pack('>I',struct.unpack('>I',IPchr)[0] + 1)
                                #numIP = (ord(IPchr[0])<<24) + (ord(IPchr[1])<<16) + (ord(IPchr[2])<<8) + ord(IPchr[3]) + 1
                                #IPchr = chr(numIP >>24) + chr((numIP >>16) & 0xff) + chr((numIP >>8)  & 0xff) + chr(numIP& 0xff)
                                self.clients[key] = {"aliveTime": time.time(),
                                                    "localIPn": IPchr}
                                localIP = socket.inet_ntoa(IPchr)
                                parameters['address'] = localIP+',32'
                                print "New Client from", src, "request IP", localIP
                                print chr(0) + " ".join(["%s,%s" % (k[0], v) for k, v in parameters.items()])
                                self.udpfd.sendto(chr(0) + " ".join(["%s,%s" % (k[0], v) for k, v in parameters.items()]), src)
                        except Exception,e:
                            print e
                            print "Need valid password from", src 
                            self.udpfd.sendto(chr(0) + "LOGIN:PASSWORD", src) 
                    else:
                        # Simply write the packet to local or forward them to other clients ??? 
                        if data[0] != chr(0): 
                            os.write(self.tfd, data) 
                            self.clients[key]["aliveTime"] = time.time()


def usage(status = 0):
    print "Usage: %s [-p port|-k key] [-m mtu] [-d dns] [-r route]" % (sys.argv[0])
    sys.exit(status)

def on_exit(no, info):
    raise Exception("TERM signal caught!")

if __name__=="__main__":
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)-8s %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S', filemode='a+')
    parameters = {}
    opts = getopt.getopt(sys.argv[1:],"p:k:m:d:r:h:")
    for opt,optarg in opts[0]:
        if opt == "-h":
            usage()
        elif opt == "-p":
            PORT = int(optarg)
        elif opt == "-k":
            KEY  = optarg
        elif opt == "-m":
            parameters['mtu'] = optarg
        elif opt == "-d":
            parameters['dns'] = optarg
        elif opt == "-r":
            parameters['route'] = optarg
    parameters['address'] = IFACE_IP

    if  PORT == 0 or not KEY or len(parameters.keys()) < 3:
        usage(1)

    tun = Tunnel()
    tun.create()
    tun.config(IFACE_IP)
    signal.signal(signal.SIGTERM, on_exit)
    signal.signal(signal.SIGTSTP, on_exit)
    try:
        tun.run()
    except KeyboardInterrupt:
        pass
    except:
        print traceback.format_exc()
    finally:
        tun.close()

