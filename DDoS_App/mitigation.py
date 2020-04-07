import os
import subprocess as sp
from netmiko import ConnectHandler   # netmiko 2.4.2

def mitigation(test_capture):
# [54394, 185, 185, 185, 185]
	nsot = { 'web_server':{'ipv4':'172.16.100.1', 'mac':'08:00:27:1a:59:21'},
			 'host1':{'ipv4':'172.16.100.2', 'mac':'08:00:27:49:a6:49'},
			 'host2':{'ipv4':'172.16.100.3', 'mac':'08:00:27:81:4a:79'}}

	command = 'tshark -r ' + test_capture + ' -T fields -e ip.src ip.dst==172.16.100.1 > src_ip.txt'
	os.system(command)

	command = 'tshark -r ' + test_capture + ' -T fields -e eth.addr ip.dst==172.16.100.1 > src_dest_mac.txt'
	os.system(command)

	
	# direct telnet into ovs using netmiko
	ovs = {
		'device_type': 'generic_termserver_telnet',
		'ip':   '192.168.160.128',
		'port': 5000,
	}

	net_connect = ConnectHandler(**ovs) 
	
	fp1 = open('src_ip.txt','r')
	lines = fp1.readlines()
	fp1.close()	
	
	fp2 = open('src_dest_mac.txt','r')
	LINES = fp2.readlines()
	fp2.close()	
	
	ips = []
	macs = []
	
	# List of all Source IPs
	for line in lines:
		line=line.replace('\n','')
		if line in ips:
			pass
		else:
			ips.append(line)

	# List of all MAC addresses
	for LINE in LINES:
		LINE = LINE.split(',')[1]
		if LINE in macs:
			pass
		else:
			macs.append(LINE)

	ip_legit = []
	ip_attack = []
	
	# Identifying the legitimate traffic using http.request and http.response packets
	for ip in ips:
		command = 'tshark -r ' + test_capture + ' -Y "(ip.src==' + ip + ')&&(http.request)" | wc -l'
		http_req = int((sp.getoutput(command)).split('\n')[1])
		command = 'tshark -r ' + test_capture + ' -Y "((ip.dst==' + ip + ')&&(http.response)" | wc -l'
		http_resp = int((sp.getoutput(command)).split('\n')[1])
		if http_req == 0 and http_resp == 0:
			ip_attack.append(ip)
		else:
			ip_legit.append(ip)

	# Collecting attack IP's MAC addresses
	 # All MAC - Legit Traffic MAC = List of Attack MAC 
	for ip in ip_legit:
		if (ip == nsot['host1']['ipv4']):
			macs.remove(nsot['host1']['mac'])
		elif (ip == nsot['host2']['ipv4']):
			macs.remove(nsot['host2']['mac'])

	# Adding DDoS Mitigation OvS flow entries			 
	for ip in ip_attack:
		if (ip == nsot['host1']['ipv4']):
			net_connect.send_command(' ovs-ofctl add-flow br0 "table=0, priority=10, in_port=1, action=drop" ')
			print("\nhost1 is compramised. Added flow rule on the OvS to block any traffic from host1")
		elif (ip == nsot['host2']['ipv4']):
			net_connect.send_command(' ovs-ofctl add-flow br0 "table=0, priority=10, in_port=2, action=drop" ')
			print("\nhost2 is compramised. Added flow rule on the OvS to block any traffic from host2")
		else:
			print("\nThe webpage is only accessible to two internal hosts, this attack is done using other IP Pool. Checking for the MAC address used during the attack.")
			for mac in macs:
				if (mac == nsot['host1']['mac']):
					net_connect.send_command(' ovs-ofctl add-flow br0 "table=0, priority=10, in_port=1, action=drop" ')
					print("\nThe attack source mac is of host1 port. Added flow rule on the OvS to block any traffic from host1")
				elif (mac == nsot['host2']['mac']):
					net_connect.send_command(' ovs-ofctl add-flow br0 "table=0, priority=10, in_port=2, action=drop" ')
					print("\nThe attack source mac is of host2 port. Added flow rule on the OvS to block any traffic from host1")
				else:
					print("\nMore packet analysis needs to be done. PLEASE CONTACT NETWORK ADMIN TEAM")
									
		




