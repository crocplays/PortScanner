from scapy.all import *
#import logging

def isTCP(p):
    return TCP in p

def scan(ip,port):
    """prints the status of a port. recieves ip,port """
    dstip=ip
    dstport=port
    pack = sr1(IP(dst= dstip)/TCP(dport = dstport),timeout = 10)
    
    if ((pack[0].haslayer(TCP)==1)):
        print " "
        
        if(pack[TCP].flags == 18) or (pack[TCP].flags == 16):
            print "port " + str(dstport) +" is open"
            openPorts.append(dstport)
        elif((pack[TCP].flags == 4) or (pack[TCP].flags == 20) ):
            print "port "+ str(dstport) + " is closed"
        

global openPorts
openPorts = list()

targetIP = input("enter the target's ip address: ")
#there are 65535 ports in a computer
for i in range(200+1):
    scan(targetIP,i)
    

print openPorts



