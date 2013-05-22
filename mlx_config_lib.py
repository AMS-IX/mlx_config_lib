#	This program is free software: you can redistribute it and/or modify
#	it under the terms of the GNU General Public License as published by
#	the Free Software Foundation, either version 3 of the License, or
#	(at your option) any later version.
#
#	This program is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#	GNU General Public License for more details.
#
#	You should have received a copy of the GNU General Public License
#	along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#	Copyright 2013, AMS-IX
#	Contact: stefan.plug@ams-ix.net
#
#	This library is used with Exscript (https://github.com/knipknap/exscript/wiki) to configure so called 'snakes' 
#	on Brocade MLX(e) switches. A snake is a port/VLAN configuration where a packet traverses the same switch several 
#	times but each time through another port. This enables us to stress test multiple ports at once.
#
#!/usr/bin/python -Btt

import time
import sys
import re
from Exscript import Account
from Exscript.protocols import SSH2
from Exscript.protocols import Telnet
from Exscript.util.match import first_match
from Exscript.util.match import any_match
from Exscript.util.interact import read_login



############################################## sub functions ####################################################################
def login(switch, username, password, verbose):
	conn = SSH2()
	#conn = Telnet()					#You want to use Telnet? really?! sigh, well I probably cannot stop you...
	conn.debug = 0						#Exscript debugging info 0-5
	if verbose == 1:
		conn.stdout = sys.stdout		#To get line-by-line input/output from the switch
	conn.connect(switch)				#SSH/Telnet connect
	account = Account(name = username, password = '', password2 = password)
	conn.login(account) 				#enable login 
	return conn

def quit(conn):
	conn.execute('quit')
	#this doesnt seem to really shut down the SSH connection (a subsequent 'exit' bugs out), but at least we go back to usermode getting in no ones way, in the future we should find a nicer way to quit.

##############################################################################################################
# This function returns an array with the individual port names from a port range like (9/1..8, 10..12/1..8) #
##############################################################################################################
def raise_error(error, conn):
	try:
		error[0]
	except:
		return
	quit(conn)
	msg = ''
	for i in error:
		msg = msg + '\n----------\n'+ i
	msg = msg + '\n----------'
	raise Exception(msg)

def port_extractor(snakerange):
	#The users input first and last ports should be connected to the Anritsu, but you can force the first and last like this: snakerange = '10/1, 9/1..8, 10/2'
	allranges = re.split(',\s', snakerange)
	portarray = []

	teller = 0
	for ranges in allranges:
		mod_port = re.split('/', allranges[teller])
		teller = teller + 1
		modrange_extremes = re.split('\.\.', mod_port[0])
		portrange_extremes = re.split('\.\.', mod_port[1])

		try:
			modrange = range(int(modrange_extremes[0]), int(modrange_extremes[1]) + 1)
		except IndexError:
			modrange = [int(modrange_extremes[0])]
		try:
			portrange = range(int(portrange_extremes[0]), int(portrange_extremes[1]) + 1)
		except IndexError:
			portrange = [int(portrange_extremes[0])]

		for mod in modrange:
			for port in portrange:
				portarray.append('ethernet ' + str(mod) + '/' + str(port))

	return portarray

def port_status_check (port, conn):
	conn.execute('show interfaces brief '+ port)
	Link = first_match(conn, r'(Disab)')
	if Link == 'Disab':
		return 1
	Link = first_match(conn, r'(Empty)')
	if Link == 'Empty':
		return 2
	Link = first_match(conn, r'(Down)')
	if Link == 'Down':
		return 3
	Link = first_match(conn, r'(Up)')
	if Link == 'Up':
		Port_State = first_match(conn, r'(Forward)')
		if Port_State == 'Forward':
			return 4
		#There should be other possibilities than Port_State=Forward right?
	return 0

def tagged (port, currentvlan, error, conn):
	conn.execute('tagged ' + port)
	error1 = any_match(conn, r'(Error: port)')
	error2 = any_match(conn, r'(has routing configuration)')
	if (error1!=[])and(error2!=[]):
		error.append(port + ' has routing information on it')

def untagged (port, currentvlan, error, conn):
	currentvlan = str(currentvlan)
	conn.execute('untagged ' + port)
	error1 = any_match(conn, r'(Error: ports)')
	error2 = any_match(conn, r'(are untagged in some user vlans)')
	if (error1!=[])and(error2!=[]):
		#Check if the VLAN error was becouse the port is already in currentvlan, if so then leave it there
		conn.execute('show vlan ' + port)
		vlan = first_match(conn, r'(VLAN: [0-9]+)')
		vlan = first_match(vlan, r'([0-9]+)') 
		if (vlan != currentvlan):
			#Check if the port is already in another snake VLAN 'SNAKE-VLAN', if so then we may replace it
			conn.execute('show vlan brief | include ' + vlan +'[\ t]')
			vlan_name = first_match(conn, r'(SNAKE-TEST)')
			if vlan_name == 'SNAKE-TEST':
				conn.execute('vlan '+ vlan)
				conn.execute('no untagged ' + port)
				conn.execute('vlan ' + currentvlan)
				conn.execute('untagged ' + port)
			else: 
				error.append(port + ' is already untagged in ' + vlan)

def get_port_dbm_and_type(port, error, conn):
	port_type_tx_rx = [port, 'unknown', 'None', 'None']
	conn.execute('show media '+ port +' | include Type')
	port_type_tx_rx[1] = first_match(conn, r'(10GE LR|10GE ER|100GE 10x10|100GE LR4)')
	if port_type_tx_rx[1] == 'unknown':   
		error.append(port + ' has an unknown port-type, please update the script to include it')

	port_modport = re.split(' ', port)
	port_module = re.split('/', port_modport[1])
	conn.execute('show  optic '+ port_module[0] +' | include ' + port_modport[1] + '[\ t]')	

	port_tx_rx = any_match(conn, r'([-]?[0-9]*\.[0-9]*[ \t]dBm[ \t]+[-]?[0-9]*\.[0-9]*[ \t]dBm)')
	port_tx_rx = re.split('\s+', str(port_tx_rx))
	port_tx = port_tx_rx[0]
	port_tx = re.split("'", port_tx)
	port_type_tx_rx[2] = port_tx[1]
	port_type_tx_rx[3] = port_tx_rx[2]
	
	return port_type_tx_rx

def port_dbm_check(port_type_tx_rx, error):
#https://www.ams-ix.net/technical/specifications-descriptions/interface-cabling-specifications 
	if port_type_tx_rx[1] == '10GE LR':
		low_tx = -4.5
		high_tx = 0
		low_rx = -13.2
		high_rx = 0.5

	if port_type_tx_rx[1] == '10GE ER':
		low_tx = -1
		high_tx = 2
		low_rx = -16.9
		high_rx = -1

	if port_type_tx_rx[1] == '100GE 10x10':
		low_tx = 3.1
		high_tx = 13
		low_rx = 2.5
		high_rx = 13

	if port_type_tx_rx[1] == '100GBASE-LR4':
		low_tx = 5.7
		high_tx = 10.5
		low_rx = 1.4
		high_rx = 14.5

	if float(port_type_tx_rx[2]) < low_tx:
		error.append(port_type_tx_rx[0] + ' has a too LOW-TX: '+ port_type_tx_rx[2] +', '+ port_type_tx_rx[1] +' Tx range: '+ str(low_tx) +' to '+ str(high_tx))
	elif float(port_type_tx_rx[2]) > high_tx:
		error.append(port_type_tx_rx[0] + ' has a too HIGH-TX: ' + port_type_tx_rx[2] +', '+ port_type_tx_rx[1] +' Tx range: '+ str(low_tx) +' to '+ str(high_tx))
	if float(port_type_tx_rx[3]) < low_rx:
		error.append(port_type_tx_rx[0] + ' has a too LOW-RX: '+ port_type_tx_rx[3] +', '+ port_type_tx_rx[1] +' Rx range: '+ str(low_rx) +' to '+ str(high_rx))
	elif float(port_type_tx_rx[3]) > high_rx:
		error.append(port_type_tx_rx[0] + ' has a too HIGH-RX: ' + port_type_tx_rx[3] +', '+ port_type_tx_rx[1] +' Rx range: '+ str(low_rx) +' to '+ str(high_rx))

#Is there a better way to check if this port is really attached to the tester? now it only check if it comes up, what proves that it really is the tester? maybe use LLDP? maybe see on the tester if a module comes up (threads)
def main_port_up_bringer(mainport1, mainport2, timer, error, conn):
	#bring the first main port up, this port should come up because it is directly attached to a tester 
	success = 0
	conn.execute('interface ' + mainport1)
	conn.execute('port-name SNAKETEST: MAINPORT-1')
	conn.execute('enable')
	for teller in range (0, timer + 1):
		time.sleep(1)
		if (port_status_check(mainport1, conn) == 4):
			success = 1
			mainport1_type_tx_rx = get_port_dbm_and_type(mainport1, error, conn)
			port_dbm_check(mainport1_type_tx_rx, error)
			conn.execute('port-name SNAKETEST: mainport passed')
			break
	if (success == 0):
		conn.execute('disable')
		conn.execute('port-name SNAKETEST: mainport did not come up')
		error.append(mainport1 + ' should be directly connected to a tester but it did not come up, please check the connection')

	if mainport2 != None:
	#bring the second main port up, this port should come up because it is directly attached to a tester 
		success = 0
		conn.execute('interface ' + mainport2)
		conn.execute('port-name SNAKETEST: MAINPORT-2')
		conn.execute('enable')
		for teller in range (0, timer + 1):
			time.sleep(1)
			if (port_status_check(mainport2, conn) == 4):
				success = 1
				mainport2_type_tx_rx = get_port_dbm_and_type(mainport2, error, conn)
				port_dbm_check(mainport2_type_tx_rx, error)
				conn.execute('port-name SNAKETEST: mainport passed')
				break
		if (success == 0):
			conn.execute('disable')
			conn.execute('port-name SNAKETEST: mainport did not come up')
			conn.execute('interface ' + mainport1)
			conn.execute('disable')
			error.append(mainport2 + ' should be directly connected to a tester but it did not come up, please check the connection')

	conn.execute('exit')

def snake_port_up_bringer(snakeport1, snakeport2, timer, dBloss, error, conn):
	#bring the first port up, this port should stay down (if it comes up then we must have a misconfig) 
	conn.execute('interface ' + snakeport1)
	conn.execute('port-name SNAKETEST: SNAKEPORT')
	conn.execute('enable')
	for teller in range (0, timer + 1):
		time.sleep(1)
		if (port_status_check(snakeport1, conn) != 3):
			conn.execute('disable')
			conn.execute('port-name SNAKETEST: ERROR: Should have stayed Down, check connection to ' + snakeport2)
			error.append(snakeport1 + ' should be in the Down state after enabling, but it is not, Please check the connection to ' + snakeport2)
			return
	conn.execute('disable')

	#bring the second port up, this port should stay down (if it comes up then we must have a misconfig) 
	conn.execute('interface ' + snakeport2)
	conn.execute('port-name SNAKETEST: SNAKEPORT')
	conn.execute('enable')
	for teller in range (0, timer + 1):
		time.sleep(1)
		if (port_status_check(snakeport2, conn) != 3):
			conn.execute('disable')
			conn.execute('port-name SNAKETEST: ERROR: Should have stayed Down, check connection to ' + snakeport1)
			error.append(snakeport2 + ' should be in the Down state after enabling, but it is not, Please check the connection to ' + snakeport1)
			return

	#now bring the first port up again, this port should now come up (if it stays down then we must have a misconfig or a dirty fiber?) 
	conn.execute('interface ' + snakeport1)
	conn.execute('enable')
	for teller in range (0, timer + 1):
		time.sleep(1)
		if (port_status_check(snakeport1, conn) == 4):
			break
		if (teller == timer):
			conn.execute('disable')
			conn.execute('port-name SNAKETEST: ERROR: Should have come Up, check connection to ' + snakeport2)
			conn.execute('interface ' + snakeport2)
			conn.execute('port-name SNAKETEST: ERROR: ' + snakeport1 + ' did not come up')
			conn.execute('disable')
			error.append(snakeport1 + ' should have come up, but it did not, please check the connection to ' + snakeport2)
			return

	#now check the second port again, it should now also be up (if it stays down then we must have a misconfig, why did the second one come up?)
	for teller in range (0, timer + 1):    
		time.sleep(1)
		if (port_status_check(snakeport2, conn) == 4):
			break
		if (teller == timer):
			conn.execute('disable')
			conn.execute('port-name SNAKETEST: ERROR: This Int came up but ' + snakeport2 + 'didnt')
			conn.execute('interface ' + snakeport2)
			conn.execute('disable')
			conn.execute('port-name SNAKETEST: ERROR: Should have come Up, check connection to ' + snakeport1)
			error.append(snakeport2 + ' should have come up, but it did not, please check the connection to ' + snakeport1)
			return

	new_error = len(error)
	snakeport1_type_tx_rx = get_port_dbm_and_type(snakeport1, error, conn)
	port_dbm_check(snakeport1_type_tx_rx, error)
	snakeport2_type_tx_rx = get_port_dbm_and_type(snakeport2, error, conn)
	port_dbm_check(snakeport2_type_tx_rx, error)
	try:
		error[new_error]
	except:
		dB_loss_1_to_2 = float(snakeport1_type_tx_rx[2]) - float(snakeport2_type_tx_rx[3])
		dB_loss_2_to_1 = float(snakeport2_type_tx_rx[2]) - float(snakeport1_type_tx_rx[3])
		dBloss.append(dB_loss_1_to_2)
		dBloss.append(dB_loss_2_to_1)

		conn.execute('port-name SNAKETEST: passed, to ' + snakeport2)
		conn.execute('interface ' + snakeport2)
		conn.execute('port-name SNAKETEST: passed, to ' + snakeport1)
		conn.execute('exit')
		return
	conn.execute('port-name SNAKETEST: ERROR: check RX/TX to ' + snakeport2)
	conn.execute('interface ' + snakeport2)
	conn.execute('port-name SNAKETEST: ERROR: check RX/TX to ' + snakeport1)
	conn.execute('exit')

def port_disable_check(snakearray, error, conn):
	for port in snakearray:
		portcheck = port_status_check(port, conn)
		if portcheck == 0:
			error.append(port +' I have no idea what this port is doing, please make sure you entered the correct port, if so, then manually disable this port first')
		elif portcheck == 2:	
			error.append(port +' is Empty, please make sure you entered the correct port, and/or that the optic is not broken. Also remember to manually disable this port')
		elif portcheck == 3:	
			error.append(port +' is Down, please make sure you entered the correct port, if so, then manually disable this port first')
		if portcheck == 4:
			error.append(port +' is UP/Forward please make sure you entered the correct port! if so, then manually disable this port first')
	raise_error(error, conn)

def remove_vlans(snakearray, conn):
	for port in snakearray:
		conn.execute('show vlan ' + port)
		vlan = first_match(conn, r'(VLAN: [0-9]+)')
		vlan = re.split(' ', vlan)
		conn.execute('no vlan ' + vlan[1])
		error1 = any_match(conn, r'(Error: Cannot undo the configuration as)')
		error2 = any_match(conn, r'(session is using this mode\.)')
		if (error1!=[])and(error2!=[]):
			quit(conn)
			raise Exception('Another user is already using this mode, remove him/her/it so we can move on')

############################################## Main callable functions ####################################################################

def send_command(switch, username, password, verbose, command):
	conn = login(switch, username, password, verbose)
	conn.execute(command)
	quit(conn)

def add_automatic(switch, username, password, verbose, snakerange, timer, snakevlan):
	error = []
	snakearray = port_extractor(snakerange)	
	decider = len(snakearray) % 2
	if decider == 0:
		add_even(switch, username, password, verbose, snakerange, snakevlan, timer, error)
	else:
		add_uneven(switch, username, password, verbose, snakerange, snakevlan, timer, error)

def add_uneven(switch, username, password, verbose, snakerange, snakevlan, timer, error):
	snakearray = port_extractor(snakerange)
	if len(snakearray) % 2 != 1:
		raise Exception('Please use a port range with an uneven number of ports')

	conn = login(switch, username, password, verbose)
	port_disable_check(snakearray, error, conn)

	conn.execute('configure terminal')
	#remove_check('no vlan '+ str(snakevlan), conn)
	conn.execute('vlan '+ str(snakevlan) +' name SNAKE-TEST-1')	
	tagged(snakearray[0], snakevlan, error, conn)
	untagged(snakearray[1], snakevlan, error, conn)
	#remove_check('no vlan '+ str(snakevlan + 1), error, conn)
	conn.execute('vlan '+ str(snakevlan + 1) + ' name SNAKE-TEST-2')
	tagged(snakearray[0], snakevlan + 1, error, conn)
	untagged(snakearray[len(snakearray) - 1], snakevlan + 1, error, conn)

	teller = 2
	snakevlan = snakevlan + 2
	while teller < len(snakearray) - 1:
		conn.execute('vlan ' + str(snakevlan) + ' name SNAKE-TEST') # there should be a no vlan check first, to see if it already exists?
		untagged(snakearray[teller], snakevlan, error, conn)
		untagged(snakearray[teller + 1], snakevlan, error, conn)
		teller = teller + 2
		snakevlan = snakevlan + 1
	raise_error(error, conn)

	#bring the ports up
	main_port_up_bringer(snakearray[0], None, timer, error, conn)
	dBloss = []
	teller = 1
	while teller < len(snakearray) - 1:
		snake_port_up_bringer(snakearray[teller], snakearray[teller + 1], timer, dBloss, error, conn)		#check if these 2 ports are connected to eachother, so if they come up and go down at the same time
		teller = teller + 2

	try:
		error[0]
	except:
		for port in snakearray:
			print 'clear statistics is buggy'
			#conn.execute('clear statistics '+ port)
		quit(conn)
		if verbose == 1: # THIS NEEDS TO BE CHANGED SO SCAPYTAIN CAN ALSO USE IT, scapytain doesnt like prints as I remember
			print '\ndB loss:'
			teller = 1
			while teller < len(snakearray) - 1:
				print '----------'
				print str(snakearray[teller]) +' > '+ str(snakearray[teller + 1]) +' = '+ str(dBloss[teller - 1]) +'dB'
				print str(snakearray[teller + 1]) +' > '+ str(snakearray[teller]) +' = '+ str(dBloss[teller]) +'dB'
				teller = teller + 2
			print '----------'
			return

	for port in snakearray:
		conn.execute('interface ' + port)
		conn.execute('disable')
	remove_vlans(snakearray, conn)
	raise_error(error, conn)

def add_even(switch, username, password, verbose, snakerange, snakevlan, timer, error):
	snakearray = port_extractor(snakerange)
	if len(snakearray) % 2 != 0:
		raise Exception('Please use a port range with an even number of ports')

	conn = login(switch, username, password, verbose)
	port_disable_check(snakearray, error, conn)
	conn.execute('configure terminal')

	teller = 0
	while teller < len(snakearray):
		# there should be a no vlan check first, to see if it already exists?
		conn.execute('vlan ' + str(snakevlan) + ' name SNAKE-TEST')
		untagged(snakearray[teller], snakevlan, error, conn)
		untagged(snakearray[teller + 1], snakevlan, error, conn)
		teller = teller + 2
		snakevlan = snakevlan + 1
	raise_error(error, conn)

	#Now we can bring the ports up
	main_port_up_bringer(snakearray[0], snakearray[len(snakearray) - 1], timer, error, conn)
	dBloss = []
	teller = 1
	while teller < len(snakearray) - 1:
		snake_port_up_bringer(snakearray[teller], snakearray[teller + 1], timer, dBloss, error, conn)		#check if these 2 ports are connected to eachother, so if they come up and go down at the same time
		teller = teller + 2

	try:
		error[0]
	except:
		for port in snakearray:
			print 'clear statistics is buggy'
			#conn.execute('clear statistics '+ port)
		quit(conn)
		if verbose == 1: # THIS NEEDS TO BE CHANGED SO SCAPYTAIN CAN ALSO USE IT, scapytain doesnt like prints as I remember
			print '\ndB loss:'
			teller = 1
			while teller < len(snakearray) - 1:
				print '----------'
				print str(snakearray[teller]) +' > '+ str(snakearray[teller + 1]) +' = '+ str(dBloss[teller - 1]) +' dB'
				print str(snakearray[teller + 1]) +' > '+ str(snakearray[teller]) +' = '+ str(dBloss[teller]) +' dB'
				teller = teller + 2
			print '----------'
		return

	for port in snakearray:
		conn.execute('interface ' + port)
		conn.execute('disable')
	remove_vlans(snakearray, conn)
	raise_error(error, conn)

def port_FREE(switch, username, password, verbose, snakerange):
	error = []
	snakearray = port_extractor(snakerange)
	conn = login(switch, username, password, verbose)
#first check if we may disable all the ports in the snake-array, is there a 'SNAKEPORT' in its port-name?
	for port in snakearray:
		conn.execute('show interfaces '+ port + ' | include Port name')   
		maydisable = first_match(conn, r'(SNAKETEST:)')
		if maydisable != 'SNAKETEST:':
			error.append('interface ' + port + ' has no port-name with "SNAKETEST", I won\'t continue')
	raise_error(error, conn)

#we can go ahead and disable the ports
	conn.execute('configure terminal')
	for port in snakearray:
		conn.execute('interface ' + port)
		conn.execute('disable')
		conn.execute('port-name FREE')
		#conn.execute('clear statistics '+ port)

#remove the VLANs
	remove_vlans(snakearray, conn)
	quit(conn)


### Callable function to configure MAC filtering ###

def set_mac_acl(switch, username, password, verbose, input_port, allowed_mac):
	"""
	SSH@gigantix(config)#mac access-list 'in-13-1'
	SSH@gigantix(config-mac-acl-'in-13-1')#permit 0001.0303.0000 FFFF.FFFF.FFFF any any 
	SSH@gigantix(config-mac-acl-'in-13-1')#deny any any any log
	SSH@gigantix(config-mac-acl-'in-13-1')#int ethernet 13/1
	SSH@gigantix(config-if-e10000-13/1)#mac access-group 'in-13-1' in 
	SSH@gigantix(config-if-e10000-13/1)#mac access-group enable-deny-logging hw-drop
	"""
	port_array = port_extractor(input_port)

#If we find a MAC address from the python-anritsu library, remove the '#H' prefix in the MAC address
	if allowed_mac.find('#H') != -1:
		allowed_mac = allowed_mac.replace("#H", "", 1)
		allowed_mac = str(allowed_mac[0:4] + '.' + allowed_mac[4:8] + '.' + allowed_mac[8:12])
	conn = login(switch, username, password, verbose)
	conn.execute('configure terminal')

	for port in port_array:
		conn.set_prompt(r'(config-mac-acl)')
		acl_name = port_array[0].replace("ethernet ", "", 1)
		acl_name = acl_name.replace("/", "-", 1)
		conn.execute('mac access-list in-' + acl_name)
		conn.execute('permit ' + allowed_mac + ' FFFF.FFFF.FFFF any any')
		conn.execute('deny any any any log')
		conn.execute('interface ' + port)
		conn.execute('mac access-group in-' + acl_name + ' in')
		conn.execute('mac access-group enable-deny-logging hw-drop')

def remove_mac_acl(switch, username, password, verbose, input_port, allowed_mac):
	"""
	no mac access-group in-13-1 in
	no mac access-group enable-deny-logging hw-drop
	no mac access-group enable-deny-logging
	no mac access-list in-13-1
	"""
	port_array = port_extractor(input_port)

	#If we find a MAC address from the python-anritsu library, remove the '#H' prefix in the MAC address
	if allowed_mac.find('#H') != -1:
		allowed_mac = allowed_mac.replace("#H", "", 1)
		allowed_mac = str(allowed_mac[0:4] + '.' + allowed_mac[4:8] + '.' + allowed_mac[8:12])
	conn = login(switch, username, password, verbose)
	conn.execute('configure terminal')

	for port in port_array:
		conn.execute('interface ' + port)
		conn.execute('no mac access-group enable-deny-logging hw-drop')
		conn.execute('no mac access-group enable-deny-logging')
		acl_name = port_array[0].replace("ethernet ", "", 1)
		acl_name = acl_name.replace("/", "-", 1)
		conn.execute('no mac access-group in-' + acl_name + ' in')
		conn.set_prompt('config')
		conn.execute('exit')
		conn.execute('no mac access-list in-' + acl_name)

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4

#to set the promt, note config-if is no longer needed, but there mighht be other cases in the future:
#conn.set_prompt(r'(config-if)')
#and to unset it
#conn.set_prompt()
