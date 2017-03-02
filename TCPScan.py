from scapy.all import *
#import logging

def isTCP(p):
    return TCP in p

dstip='10.30.56.205'
dstport=80
pack = sr1(IP(dst= dstip)/TCP(dport = dstport),timeout = 10)


"""
print pack
print pack.show()
print pack[TCP].flags
"""


if ((pack[0].haslayer(TCP)==1)):
    print " "
    if(pack[TCP].flags == 18) or (pack[TCP].flags == 16):
        print "port " + str(dstport) +" is open"
    elif((pack[TCP].flags == 4) or (pack[TCP].flags == 20) ):
        print "port "+ str(dstport) + " is closed"



