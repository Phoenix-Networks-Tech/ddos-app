#!/usr/bin/env python

import numpy as np
import subprocess as sp
from sklearn.preprocessing import normalize

stable1 = []
stable2 = []
stable3 = []
attack1 = []
attack2 = []
attack3 = []
stable_captures = ['stable1', 'stable2', 'stable3']
attack_captures = ['attack1', 'attack2', 'attack3']

# extracting data

''' stable network packets '''
''' syn, syn_ack, ack, http_req http_resp '''

for capture in stable_captures:
	command = 'tshark -r ./lab8/train/' + capture + '.pcap -Y "(tcp.flags.syn==1)&&(tcp.flags.ack==0)&&(tcp.flags.fin==0)" | wc -l'
	tcp_syn = int((sp.getoutput(command)).split('\n')[1])

	command = 'tshark -r ./lab8/train/' + capture + '.pcap -Y "(tcp.flags.syn==1)&&(tcp.flags.ack==1)&&(tcp.flags.fin==0)" | wc -l'
	tcp_syn_ack = int((sp.getoutput(command)).split('\n')[1])
	
	command = 'tshark -r ./lab8/train/' + capture + '.pcap -Y "(tcp.flags.syn==0)&&(tcp.flags.ack==1)&&(tcp.flags.fin==0)" | wc -l'
	tcp_ack = int((sp.getoutput(command)).split('\n')[1])	
	
	command = 'tshark -r ./lab8/train/' + capture + '.pcap -Y "(http.request)" | wc -l'
	http_req = int((sp.getoutput(command)).split('\n')[1])		
	
	command = 'tshark -r ./lab8/train/' + capture + '.pcap -Y "(http.response)" | wc -l'
	http_resp = int((sp.getoutput(command)).split('\n')[1])	
	
	if (capture == 'stable1'):
		stable1.append(tcp_syn)
		stable1.append(tcp_syn_ack)
		stable1.append(int(tcp_ack/6))
		stable1.append(http_req)
		stable1.append(http_resp)

	elif (capture == 'stable2'):
		stable2.append(tcp_syn)
		stable2.append(tcp_syn_ack)
		stable2.append(int(tcp_ack/6))
		stable2.append(http_req)
		stable2.append(http_resp)

	elif (capture == 'stable3'):
		stable3.append(tcp_syn)
		stable3.append(tcp_syn_ack)
		stable3.append(int(tcp_ack/6))
		stable3.append(http_req)
		stable3.append(http_resp)
	
	else:
		pass


''' attack network packets '''
''' syn, syn_ack, ack, http_req http_resp '''

for capture in attack_captures:
	command = 'tshark -r ./lab8/train/' + capture + '.pcap -Y "(tcp.flags.syn==1)&&(tcp.flags.ack==0)&&(tcp.flags.fin==0)" | wc -l'
	tcp_syn = int((sp.getoutput(command)).split('\n')[1])

	command = 'tshark -r ./lab8/train/' + capture + '.pcap -Y "(tcp.flags.syn==1)&&(tcp.flags.ack==1)&&(tcp.flags.fin==0)" | wc -l'
	tcp_syn_ack = int((sp.getoutput(command)).split('\n')[1])
	
	command = 'tshark -r ./lab8/train/' + capture + '.pcap -Y "(tcp.flags.syn==0)&&(tcp.flags.ack==1)&&(tcp.flags.fin==0)" | wc -l'
	tcp_ack = int((sp.getoutput(command)).split('\n')[1])	
	
	command = 'tshark -r ./lab8/train/' + capture + '.pcap -Y "(http.request)" | wc -l'
	http_req = int((sp.getoutput(command)).split('\n')[1])		
	
	command = 'tshark -r ./lab8/train/' + capture + '.pcap -Y "(http.response)" | wc -l'
	http_resp = int((sp.getoutput(command)).split('\n')[1])	
	
	if (capture == 'attack1'):
		attack1.append(tcp_syn)
		attack1.append(tcp_syn_ack)
		attack1.append(int(tcp_ack/6))
		attack1.append(http_req)
		attack1.append(http_resp)

	elif (capture == 'attack2'):
		attack2.append(tcp_syn)
		attack2.append(tcp_syn_ack)
		attack2.append(int(tcp_ack/6))
		attack2.append(http_req)
		attack2.append(http_resp)

	elif (capture == 'attack3'):
		attack3.append(tcp_syn)
		attack3.append(tcp_syn_ack)
		attack3.append(int(tcp_ack/6))
		attack3.append(http_req)
		attack3.append(http_resp)
	
	else:
		pass
	

# normalizing the dataset and getting i ready for our model

train_data = normalize(np.array([stable1]))
train_target = np.array([0])

train_data = normalize(np.append(train_data, [attack1], axis=0))
train_target = np.append(train_target, [1])

train_data = normalize(np.append(train_data, [attack2], axis=0))
train_target = np.append(train_target, [1])

train_data = normalize(np.append(train_data, [stable2], axis=0))
train_target = np.append(train_target, [0])

train_data = normalize(np.append(train_data, [attack3], axis=0))
train_target = np.append(train_target, [1])

train_data = normalize(np.append(train_data, [stable3], axis=0))
train_target = np.append(train_target, [0])

