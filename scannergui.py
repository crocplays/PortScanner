from Tkinter import *
import datetime
from scapy.all import *
import tkMessageBox
import TCPScan
import UDPScan

def clearFields():
    """
    clears all the fields on the screen(all entries and textboxes)"""
    textBox.delete('0.0',END)
    statusText.delete('0.0',END)
    IPText.delete(0,END)
    
def checkIP(IP):
    """
    checks the IP address if the address is correct returns it if not returns 127.0.0.1 address for self scan"""
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
    time.sleep(1)
    return '127.0.0.1'


def getPorts():
    """
    returns the list of port for scanning either specific ports or all the ports"""
    ports=list()
    text=textBox.get('0.0',END)
    print text
    print len(text)
    if text[0:3]=='ALL':
        for i in xrange(65535):
            ports.append(i+1)
    else:
        p=text.split(',')
        for i in p:
            ports.append(int(i))
    return ports

def saveLog(timeOfScan,ports,protocol):
    """
    creates the new text file and then inputs all the ports' status"""
    print ports
    var2.set("   scanning complete, log saved   ")
    f=open("C:\\ScanLog_"+scanTime.strftime('_%d-%m-%y_%H:%M')+'.txt','w')
    f.write(protocol+" scan log\r\nIP address:"+IPText.get()+"\r\n"+timeOfScan)
    f.write("\r\n")
    f.write("".join(ports))
    f.close()


def scanUDP(timeOfScan,ports,IP):
    """
    scans all the ports using the UDPScan module and then prints the port status to the status textbox,
    and then calls the saveLog() function to save the log of hte scan"""
    scannedPorts=UDPScan.scan(IP,ports)
    for i in scannedPorts:
        statusText.insert('0.0',i)
    saveLog(timeOfScan,scannedPorts,"UDP")

    
def scanTCP(timeOfScan,ports,IP):
    """
    scans all the ports using the TCPScan module and then prints the port status to the status textbox,
    and then calls the saveLog() function to save the log of hte scan"""
    scannedPorts=TCPScan.scan(IP,ports)
    print scannedPorts
    for i in scannedPorts:
        statusText.insert('0.0',i)
    saveLog(timeOfScan,scannedPorts,"TCP")

def checkScan():
    """
    checks the time of the scan start to be used in saving the log file,
    gets the list of ports from getPorts(),
    checks if the IP address is correct.
    then check the type of scan (TCP or UDP) the user requested and starts the requested scan."""
    var2.set("     scanning...")
    global scanTime
    scanTime=datetime.datetime.now()
    timeOfScan= scanTime.strftime('%A, %d/%m/%y  %H:%M:%S')
    ports=getPorts()
    IP=checkIP(IPText.get())
    statusText.delete('0.0',END)
    if var.get()==1:
        scanTCP(timeOfScan,ports,IP)
    else:
        scanUDP(timeOfScan,ports,IP)

def main():     
    """
    this function sets up he GUI of the program and starts the mainloop."""
    window=Tk()
    window.resizable(width=False, height=False)
    global var
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
    global IPText
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
    global statusText
    statusText=Text(statusFrame,yscrollcommand=scrollbar2.set)
    statusText.pack(side="left")
    scrollbar2.pack(side="left",fill=Y)
    scrollbar2.config(command=statusText.yview)


    checkTCP.select()
    window.mainloop()

if __name__=="__main__":
    main()
