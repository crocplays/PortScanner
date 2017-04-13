from Tkinter import *
import datetime
from scapy.all import *
import tkMessageBox

def clearFields():
    textBox.delete('0.0',END)
    statusText.delete('0.0',END)
    IPText.delete(0,END)
def checkIP(IP):
    fields=IP.split('.')
    if len(fields)==4:

        count=0
        for i in fields:
            if int(i)>=0 and int(i)<=255:
                count+=1
        if count==4:
            return IP
    tkMessageBox.showinfo("IP error","you entered an incorrect IP address, 127.0.0.1 has been set as the target instead")
    IP='127.0.0.1'
    IPText.delete(0,END)
    IPText.insert(0,IP)
    return '127.0.0.1'

def isUDP(p):
    return UDP in p

def isICMP(p):
    return ICMP in p

def isTCP(p):
    return TCP in p

def getPorts():
    ports=list()
    text=textBox.get('1.0',END)
    print text
    if text=='ALL':
        for i in xrange(65535):
            ports.append(i)
    else:
        p=text.split(',')
        for i in p:
            ports.append(int(i))
    return ports

def saveLog(timeOfScan,ports,protocol):
    print ports
    var2.set("   scanning complete, log saved   ")
    f=open("lastScanLog",'w')
    f.write(protocol+" scan log\r\nIP address:"+IPText.get()+"\r\n"+timeOfScan)
    f.write("\r\n")
    f.write("".join(ports))
    f.close()

def scanTCP(timeOfScan,portList,dstip):
    for dstport in portList:
        ports=list()
        pack = sr1(IP(dst= dstip)/TCP(dport = dstport),timeout =2)
        if pack is not None:
            if pack[0].haslayer(TCP):
                if(pack[TCP].flags == 18) or (pack[TCP].flags == 16):
                    print "port " + str(dstport) +" is open\r\n"
                    statusText.insert('0.0',"\r\n port " + str(dstport) +" is open")
                    ports+="port " + str(dstport) +" is open\r\n"
                    openPorts.append(dstport)
                elif((pack[TCP].flags == 4) or (pack[TCP].flags == 20) ):
                    print "port "+ str(dstport) + " is closed"
                    statusText.insert('0.0',"\r\n port "+ str(dstport) + " is closed")
                    ports+="port "+ str(dstport) + " is closed\r\n"
    saveLog(timeOfScan,ports,"TCP")


def scanUDP(timeOfScan,portList,dstip):
    var2.set("     scanning...")
    openPorts = list()
    ports=list()
    for i in portList:
        pack = sr1(IP(dst=dstip)/UDP(dport=i),timeout=2)
        if pack is not None:
            
            if pack[0].haslayer(UDP):
                print "port "+ str(i) + " is open"
                statusText.insert('0.0',"\r\n port "+ str(i) + " is open")
                ports+="port "+ str(i) + " is open\r\n"
                openPorts.append(i)
            elif pack[0].haslayer(ICMP):
                print "port "+ str(i) + " is closed/filtered"
                statusText.insert('0.0',"\r\n port "+ str(i) + " is closed/filtered")
                ports+="port "+ str(i) + " is closed/filtered\r\n"
        else:
            print "port "+ str(i) + " is open/filtered"
            ports+="port "+ str(i) + " is open/filtered\r\n"
            statusText.insert('0.0',"\r\n port "+ str(i) + " is open/filtered")
    
    saveLog(timeOfScan,ports,"UDP")

def checkScan():
    var2.set("     scanning...")
    i=datetime.datetime.now()
    timeOfScan= i.strftime('%A, %d/%m/%y  %H:%M:%S')
    ports=getPorts()
    IP=checkIP(IPText.get())
    if var.get()==1:
        scanTCP(timeOfScan,ports,IP)
    else:
        scanUDP(timeOfScan,ports,IP)
        
window=Tk()
window.resizable(width=False, height=False)
var=IntVar()
global var2
var2=StringVar()

top=Frame(window)
top.pack()
middle=Frame(window)
middle.pack()
bottom=Frame(window)
bottom.pack()


descriptionFrame1=Frame(top)
descriptionFrame1.pack(side="top")
descriptionLabel1=Label(descriptionFrame1,text=" Ports:")
descriptionLabel1.pack()
textFrame=Frame(top)
textFrame.pack(side="left")
scrollbar1=Scrollbar(top)
scrollbar1.pack(side="right",fill=Y)
global textBox
textBox=Text(textFrame,yscrollcommand=scrollbar1.set)
textBox.pack(side="left")
scrollbar1.config(command=textBox.yview)


IP_Frame=Frame(middle)
IP_Frame.pack(side="top")
descriptionFrame2=Frame(IP_Frame)
descriptionFrame2.pack(side="left")
descriptionLabel2=Label(descriptionFrame2,text=" IP address:")
descriptionLabel2.pack()
IPFrame=Frame(IP_Frame)
IPFrame.pack(side="right")
IPText=Entry(IPFrame)
IPText.pack()
checkFrame=Frame(middle)
checkFrame.pack(side="left")
checkTCP=Radiobutton(checkFrame,text=" scan TCP     ",variable=var,value=1)
checkTCP.pack()
checkUDP=Radiobutton(checkFrame,text=" scan UDP     ",variable=var,value=2)
checkUDP.pack()
btnFrame=Frame(middle)
btnFrame.pack(side="left")
btnScan=Button(btnFrame,text="    Scan    ",command=checkScan)
btnScan.pack(side="left")
clrBtn=Button(btnFrame,text="    Clear   ",command=clearFields)
clrBtn.pack(side="right")
statLabelFrame=Frame(middle)
statLabelFrame.pack(side="right")
statusLabel=Label(statLabelFrame,textvariable=var2)
var2.set("     Waiting for input...")
statusLabel.pack()

statLabel=Label(bottom,text=" Port status:")
statLabel.pack()
statusFrame=Frame(bottom)
statusFrame.pack(side="bottom")
scrollbar2=Scrollbar(statusFrame)
statusText=Text(statusFrame,yscrollcommand=scrollbar2.set)
statusText.pack(side="left")
scrollbar2.pack(side="left",fill=Y)
scrollbar2.config(command=statusText.yview)


checkTCP.select()
window.mainloop()

