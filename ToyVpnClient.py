#!/usr/bin/python

'''''
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
import re
import subprocess

#SHARED_PASSWORD = hashlib.sha1("xiaoxia").digest()
TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_NO_PI = 0x1000
BUFFER_SIZE = 32767

#TIMEOUT = 60*10 # seconds

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
        ifs = fcntl.ioctl(self.tfd, TUNSETIFF, struct.pack("16sH", "tun0", IFF_TUN| IFF_NO_PI))
        self.tname = ifs[:16].strip("\x00")
        #subprocess.check_call('ifconfig tun0 %s pointopoint 10.0.0.2 up' %self.address,
        #                        shell=True)

    def close(self):
        os.close(self.tfd)

    def config(self, ip):
        print "Configuring interface %s with ip %s" % (self.tname, ip)
        os.system("ip link set %s up" % (self.tname))
        os.system("ip link set %s mtu %s" % (self.tname,self.mtu))
        os.system("ip addr add %s dev %s" % (ip, self.tname))

    def config_routes(self):
        print "Setting up new gateway ..."
        # Look for default route
        routes = os.popen("ip route show").readlines()
        defaults = [x.rstrip() for x in routes if x.startswith("default")]
        if not defaults:
            raise Exception("Default route not found, maybe not connected!")
        self.prev_gateway = defaults[0]
        self.new_gateway = "default dev %s metric 1" % (self.tname)
        self.tun_gateway = self.prev_gateway.replace("default", IP)
        self.old_dns = file("/etc/resolv.conf", "rb").read()
        # Remove default gateway
        os.system("ip route del " + self.prev_gateway)
        # Add exception for server
        os.system("ip route add " + self.tun_gateway)
        # Add new default gateway
        os.system("ip route add " + self.new_gateway)
        # Set new DNS to 8.8.8.8
        file("/etc/resolv.conf", "wb").write("nameserver %s" %self.dns)

    def restore_routes(self):
        print "Restoring previous gateway ..."
        os.system("ip route del " + self.new_gateway)
        os.system("ip route del " + self.tun_gateway)
        os.system("ip route add " + self.prev_gateway)
        file("/etc/resolv.conf", "wb").write(self.old_dns)

    def handshake(self,tunnel):
        logging.info("handshake with the server ...")
        for i in xrange(3):
            tunnel.sendall(chr(0) + KEY)
            #tunnel.shutdown(1)
        for i in xrange(50):
            time.sleep(1)
            logging.info("start to recv ")
            packet = tunnel.recv(1024)
            logging.info("recv finished == %s" %str(packet).strip())
            if (len(packet) > 0 and packet[0] == chr(0)):
                self.configure(str(packet[1:]).strip())
                return
        raise Exception("Failed to log in server.")

    def configure(self,parameters):
        logging.info("config the parameters == %s" %parameters)
        if self.tfd and parameters == self.mParameters:
            logging.info('Using the previous interface')
            return
        for parameter in parameters.split(" "):
            fields = parameter.split(",")
            if   fields[0][0] == 'm':
                self.mtu = int(fields[1])
            elif fields[0][0] == 'a':
                self.address = fields[1]
            elif fields[0][0] == 'r':
                self.route = fields[1]
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
        self.udpfd.connect((IP, PORT))
        self.handshake(self.udpfd)
        logging.info("connected successful")

        while True:
            rset = select.select([self.udpfd, self.tfd], [], [], 1)[0]
            for r in rset:
                if r == self.tfd:
                    os.write(1,'>')
                    data = os.read(self.tfd, BUFFER_SIZE)
                    if len(data):
                        self.udpfd.sendall(data)
                        data = None
                elif r == self.udpfd:

                    os.write(1,'<')
                    data = self.udpfd.recv(BUFFER_SIZE)
                    if data[0] != chr(0):
                        os.write(self.tfd, data)
                    data = None


def usage(status = 0):
    print "Usage: %s [-s server|-p port|-k passord|-h help] " % (sys.argv[0])
    sys.exit(status)

def on_exit(no, info):
    raise Exception("TERM or TSTP signal caught!" )

if __name__=="__main__":
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)-8s %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S', filemode='a+')
    opts = getopt.getopt(sys.argv[1:],"s:p:k:h:")
    IP   = ''
    PORT = 0
    KEY  = ''
    for opt,optarg in opts[0]:
        if opt == "-h":
            usage()
        elif opt == "-s":
            IP = socket.gethostbyname(optarg)
        elif opt == "-p":
            PORT = int(optarg)
        elif opt == "-k":
            KEY  = optarg

    if False == (IP and PORT):
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
