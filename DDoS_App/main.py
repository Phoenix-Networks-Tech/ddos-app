#!/usr/bin/env python

import tensorflow as tf
import numpy as np
import os.path
import sys 
from tensorflow import keras
from sklearn.preprocessing import normalize 
import subprocess as sp
import training_dataset as td
from termcolor import colored
from mitigation import mitigation

# print (tensorflow.__version__)

''' ML Training '''
print(colored("\n##### Training the Machine Learning Algorithm #####\n", "blue") )

model = keras.Sequential([
    keras.layers.Flatten(input_shape=(5,)),
    keras.layers.Dense(50, activation=tf.nn.relu),
    keras.layers.Dense(50, activation=tf.nn.relu),
    keras.layers.Dense(1)
])

model.compile(optimizer='adam', loss='mse', metrics=['mae'])

model.fit(td.train_data, td.train_target, epochs=15, batch_size=1)

print(colored("\n##### Training Completed #####\n", "green"))
	  
	  
''' Test Dataset '''
unknown1 = []
test_capture = input("\nEnter the complete path of the capture to be tested: ")
if os.path.exists(test_capture):
	pass
else:
	sys.exit("File does not exist. Exiting the program....")

command = 'tshark -r ' + test_capture + ' -Y "(tcp.flags.syn==1)&&(tcp.flags.ack==0)&&(tcp.flags.fin==0)" | wc -l'
tcp_syn = int((sp.getoutput(command)).split('\n')[1])
unknown1.append(tcp_syn)

command = 'tshark -r ' + test_capture + ' -Y "(tcp.flags.syn==1)&&(tcp.flags.ack==1)&&(tcp.flags.fin==0)" | wc -l'
tcp_syn_ack = int((sp.getoutput(command)).split('\n')[1])
unknown1.append(tcp_syn_ack)

command = 'tshark -r ' + test_capture + ' -Y "(tcp.flags.syn==0)&&(tcp.flags.ack==1)&&(tcp.flags.fin==0)" | wc -l'
tcp_ack = int((sp.getoutput(command)).split('\n')[1])	
unknown1.append(int(tcp_ack/6))

command = 'tshark -r ' + test_capture + ' -Y "(http.request)" | wc -l'
http_req = int((sp.getoutput(command)).split('\n')[1])
unknown1.append(http_req)

command = 'tshark -r ' + test_capture + ' -Y "(http.response)" | wc -l'
http_resp = int((sp.getoutput(command)).split('\n')[1])
unknown1.append(http_resp)

test_data = normalize(np.array([unknown1]))
prediction = float(model.predict(test_data)[0][0])
print("\nPrediction is:",prediction)


''' Initiating DDoS Mitigation '''
if (0 <= prediction < 0.4):
	print(colored("\nStable Network", "green"))
elif (0.4 <= prediction < 0.7):
	print(colored("\nAnomaly in the Network. Network Admin Please Check!!!", "blue"))
elif (prediction >= 0.7 ):
	print(colored("\n!!!Network Under DDoS Attack!!!\nInitiating Mitigation...", "red"))
	mitigation(test_capture)
else:
	pass
