#!/usr/bin/env python
#
# Script for decrypting DoublePulsar traffic, inspired by
# https://github.com/countercept/doublepulsar-c2-traffic-decryptor/blob/master/decrypt_doublepulsar_traffic.py
#
# It's not elegant, and it does not work with arbitrary DanderSpritz
# traffic captures. It only works with HTTP Proxy implants making reverse
# connections on port 80/443 back to PeddleCheap.
#
# Purpose is to serve as documentation for how DanderSpritz and implants communicate.
#
# Author: John Bergbom

from scapy.all import *
import sys
import re
from itertools import cycle, izip
import binascii

exponent = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x01"

if len(sys.argv) != 3 and len(sys.argv) != 4:
        print "Decrypts DoublePulsar network traffic and dumps the decrypted"
        print "traffic to a file."
        print "Usage: python " + sys.argv[0] + " file.pcap outfile.bin [ private key file ]"
        exit(1)
pcap_filename = sys.argv[1]
dump_file = sys.argv[2]
priv_key_file = None
if len(sys.argv) == 4: priv_key_file = sys.argv[3]

# https://zerosum0x0.blogspot.com/2017/04/doublepulsar-initial-smb-backdoor-ring.html
# https://github.com/countercept/doublepulsar-detection-script/blob/master/detect_doublepulsar_smb.py
def calculate_doublepulsar_xor_key(s):
	x = (2 * s ^ (((s & 0xff00 | (s << 16)) << 8) | (((s >> 16) | s & 0xff0000) >> 8)))
	x = x & 0xffffffff  # this line was added just to truncate to 32 bits
	return x

# The arch is adjacent to the XOR key in the SMB signature (in the ping response)
# https://github.com/countercept/doublepulsar-detection-script/blob/master/detect_doublepulsar_smb.py
def calculate_doublepulsar_arch(s):
	if s & 0xffffffff00000000 == 0:
		return "x86 (32-bit)"
	else:
		return "x64 (64-bit)"

def xor_decrypt(message, key):
	return ''.join(chr(ord(c) ^ ord(k)) for c, k in izip(message, cycle(key)))

def get_command(t):
	opcode = hex(((t) + (t >> 8) + (t >> 16) + (t >> 24)) & 0x000000ff)
	if opcode == "0x23":
		return "ping"
	elif opcode == "0xc8":
		return "exec"
	elif opcode == "0x77":
		return "kill"
	else:
		return "unknown"

def get_status_code(req_mid, resp_mid):
	delta = hex(resp_mid - req_mid)
	if delta == "0x10":
		return "success"
	elif delta == "0x20":
		return "invalid parameters"
	elif delta == "0x30":
		return "allocation failure"
	else:
		return "unknown"

def to_hex(s):
	hex_str = ""
	for char in s:
		hex_str += char.encode('hex')
	return hex_str

def print_req_packet_stat(packets,i,timeout):
	command = get_command(timeout)
	print "packet nbr " + str(i) + " (" + command + " request):",
	print packets[i].payload.src + ":" + str(packets[i].payload.payload.sport) + " ->",
	print packets[i].payload.dst + ":" + str(packets[i].payload.payload.dport)

def get_platform(p):
	if p == 0:
		return "win9x"
	elif p == 1:
		return "winnt"
	elif p == 2:
		return "linux"
	elif p == 3:
		return "solaris"
	elif p == 4:
		return "sunos"
	elif p == 5:
		return "aix"
	elif p == 6:
		return "bsdi"
	elif p == 7:
		return "tru64"
	elif p == 8:
		return "freebsd"
	elif p == 9:
		return "irix"
	elif p == 10:
		return "hpux"
	elif p == 11:
		return "mirapoint"
	elif p == 12:
		return "openbsd"
	elif p == 13:
		return "sco"
	elif p == 14:
		return "linux_se"
	elif p == 15:
		return "darwin"
	elif p == 16:
		return "vxworks"
	elif p == 17:
		return "psos"
	elif p == 18:
		return "winmobile"
	elif p == 19:
		return "iphone"
	elif p == 20:
		return "junos"
	elif p == 21:
		return "android"
	else:
		return "unknown"

def get_arch(a):
	if a == 0:
		return "i386"
	elif a == 1:
		return "sparc"
	elif a == 2:
		return "alpha"
	elif a == 3:
		return "arm"
	elif a == 4:
		return "ppc"
	elif a == 5:
		return "hppa1"
	elif a == 6:
		return "hppa2"
	elif a == 7:
		return "mips"
	elif a == 8:
		return "x64"
	elif a == 9:
		return "ia64"
	elif a == 10:
		return "sparc64"
	elif a == 11:
		return "mips64"
	else:
		return "unknown"

def aes_decrypt(encrypted, passphrase, IV):
	aes = AES.new(passphrase, AES.MODE_CBC, IV)
	return aes.decrypt(encrypted)

def hex_to_bin(s):
	str = s
	if str[-1:] == "L": s = str[0:len(str)-1]
	if s[0:2] == "0x": str = s[2:]
	return binascii.unhexlify(str)

xor_key = None
req_multiplex_id = None
packets = rdpcap(pcap_filename)
write_fp = open(dump_file, 'wb')
IV = None
print ""
print "Searching in pcap for implant deployment to DoublePulsar:"
print "---------------------------------------------------------"
print "Nbr packets: " + str(len(packets))
for i in range(len(packets)):
	payload = str(packets[i].payload.payload.payload)
	# Check for SMB trans2 packets having the subcommand SESSION_SETUP:
	if "\xffSMB\x32" in payload:			# if SMB trans2 command
		if "\x0e\x00" in payload[65:67]:	# if subcommand is SESSION_SETUP (request)
			req_multiplex_id = struct.unpack('<H',payload[34:36])[0]
			timeout = struct.unpack('<I',payload[49:53])[0]
			print_req_packet_stat(packets,i,timeout)
			header = payload[70:82]
			data = payload[82:]

			# If the smb packet continues, then append the subsequent packets
			# to the smb data.
			j = i
			smb_size_short_int = struct.unpack('>H', payload[39:41])[0] * 256
			while len(data) < smb_size_short_int:
				j = j + 1
				# Dirty way of checking if the next packet belongs to the same stream
				if packets[j].payload.payload.dport == 445:
					data = data + str(packets[j].payload.payload.payload)

			# Decrypt the packet
			if header != "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00":
				if xor_key is None:
					# The xor key is obtained from the four last bytes of the session parameters
					# to the SESSION_SETUP subcommand (that the client sends to the target infected
					# by DoublePulsar).
					xor_key = header[8:12]
					xor_key_int = struct.unpack('<I',xor_key)[0]
					print "packet nbr " + str(i) + ":",
					print "xor key for encrypting payload to DoublePulsar: " + hex(xor_key_int)
				decrypted_data = xor_decrypt(data, xor_key)
				write_fp.write(decrypted_data)

			if get_command(timeout) == "ping":
				prev_ping = 1
			else:
				prev_ping = 0

		elif "\x02\x00\x00\xc0" in payload[9:13]:	# if response = STATUS_NOT_IMPLEMENTED
			if req_multiplex_id is not None:
				resp_multiplex_id = struct.unpack('<H',payload[34:36])[0]
				status_code = get_status_code(req_multiplex_id,resp_multiplex_id)
				print "  packet nbr " + str(i) + " response: " + status_code
				
				req_multiplex_id = None
			if prev_ping == 1:
				signature = struct.unpack('<Q', payload[18:26])[0]
				ping_xor_key = calculate_doublepulsar_xor_key(signature)
				arch = calculate_doublepulsar_arch(signature)
				print "  packet nbr " + str(i) + " xor key in response: " + hex(ping_xor_key),
				print ", target arch: " + arch
				prev_ping = 0

write_fp.close()
print "DoublePulsar payload written to " + dump_file

# Extract the public key from the file sent to DoublePulsar:
print ""
print "Extracting public key data from pcap:"
print "-------------------------------------"
with open(dump_file,"r") as infile:
	payload = infile.read()
	pubkey_offset = payload.index(exponent) - 256 - 4
	pubkey = payload[pubkey_offset:pubkey_offset+516]
	fp = open(dump_file + ".public_key","w")
	fp.write(pubkey)
	fp.close()
	print "Public key written to " + dump_file + ".public_key"


# Print info about the public key:
with open(dump_file + ".public_key","r") as keyfile:
	content = keyfile.read()
	key_length = struct.unpack('>I', content[0:4])[0]
	print "Key length: " + str(key_length)
	modulus = content[4:260]
	print "Modulus: 0x" + to_hex(modulus)
	modulus_int = int(to_hex(modulus),16)
	pubkey_exponent = content[260:516]
	print "Public key exponent: 0x" + to_hex(pubkey_exponent)
	pubkey_exp_int = int(to_hex(pubkey_exponent),16)

# Print info about the private key if available:
privkey_exp_int = 0
if priv_key_file is not None:
	print ""
	print "Extracting private key data from provided file:"
	print "-----------------------------------------------"
	with open(priv_key_file,"r") as privkeyfile:
		content = privkeyfile.read()
		privk_modulus = content[4:260]
		if privk_modulus != modulus:
			print "Error: provided private key doesn't correspond to the network capture"
			sys.exit(1)
		privkey_exponent = content[516:772]
		if privkey_exponent == "":
			print "Error: provided private key file doesn't seem to contain a private key"
			sys.exit(2)
		privkey_exp_int = int(to_hex(privkey_exponent),16)
		prime1 = content[772:900]
		prime2 = content[900:1028]
		prime_exp1 = content[1028:1156]
		prime_exp2 = content[1156:1284]
		coeff = content[1284:1412]
		print "Private key exponent: 0x" + to_hex(privkey_exponent)
		print "Prime 1: 0x" + to_hex(prime1)
		print "Prime 2: 0x" + to_hex(prime2)
		print "Prime exponent 1: 0x" + to_hex(prime_exp1)
		print "Prime exponent 2: 0x" + to_hex(prime_exp2)
		print "Coefficient: 0x" + to_hex(coeff)


# Analyze the HTTP traffic between the implant and DanderSpritz:
# In the code, status can be:
# 0 = no packet yet seen
# 1 = initial contact from implant seen
# 2 = magic number sent to implant
# 3 = implant has sent symmetric key to DS
# 4 = DS has sent "OS version check status" message to implant
# 5 = implant has acknowledged reception of the message "OS version check status"
# 6 = DS has sent empty reply, acknowledging the acknowledgement
# 7 = implant has asked DanderSpritz for the next command to run
# 8 = DS has sent PayloadInfo run type info and File/Library info to implant
# 9 = implant has acknowledged reception of File/Library info
# 10 = DS has sent and Export name to implant
# 11 = implant has acknowledged reception of Export name and will start sending file to execute to implant
# 12 = DS is sending executable file to implant
print ""
print "Analyzing traffic between implant and DanderSpritz:"
print "---------------------------------------------------"
status = 0
for i in range(len(packets)):
	if packets[i].type == 2048:		# 2048 = IPv4
		if packets[i].payload.payload.dport == 80 or packets[i].payload.payload.dport == 443:
			payload = str(packets[i].payload.payload.payload)
			if "POST / HTTP/1.1" in payload:
				index = payload.index("\x0d\x0a\x0d\x0a") + 4
				data = payload[index:]
				conn_id = payload.split('\r\n')[2]
				id_part = conn_id.split(':')[1][2:]
				seq_num = int(conn_id.split(':')[2],16)
				payload_length = 0
				clear_text_length = 0
				symm_encr_used = 0
				if (len(data) > 0):
					clear_text_length = struct.unpack('>I', data[0:4])[0]
					length2 = int(to_hex(data[4:5]),16)
					payload_length = clear_text_length + length2
					symm_encr_used = int(to_hex(data[5:6]),16)
				if status == 0:
					print "packet nbr " + str(i) + ": initial contact from implant to DanderSpritz"
					print "  Seq nbr: " + str(seq_num)
					print "  Payload length: " + str(payload_length)
					print "  Clear text length: " + str(clear_text_length)
					print "  Symm. encr. used: " + str(symm_encr_used)
					print "  Custom header: " + conn_id
					status = 1
				elif status == 2:	# DS has sent magic number, implant now sends symmetric key
					print "packet nbr " + str(i) + ": implant sends symmetric key and platform info to DanderSpritz"
					print "  Seq nbr: " + str(seq_num)
					print "  Payload length: " + str(payload_length)
					print "  Clear text length: " + str(clear_text_length)
					print "  Symm. encr. used: " + str(symm_encr_used)
					IV = data[8+256+8:]
					encr_symm_key_int = int(to_hex(data[8:8+256]),16)
					if privkey_exp_int == 0:
						print "The encrypted symmetric key is: 0x" + hex(encr_symm_key_int)
						print "Cannot decrypt the rest of the communication because",
						print "no private key file was provided."
						exit(0)
					# the last 48 bytes are what we're interested in
					decrypted_data = hex(pow(encr_symm_key_int,privkey_exp_int,modulus_int))[-97:-1]
					print "  Decrypted data: " + decrypted_data
					print "  => interpretation:"
					major_ver = int(decrypted_data[2:4],16)
					minor_ver = int(decrypted_data[6:8],16)
					sub_ver = int(decrypted_data[4:6],16)
					print "  Implant ver: " + str(major_ver) + "." + str(minor_ver) + "." + str(sub_ver)
					index = decrypted_data.index("0000000000") - 32
					session_key = decrypted_data[16:48]
					print "  Session key: 0x" + session_key
					session_key_int = int(session_key,16)
					if session_key_int == 0:
						print "  Encryption not active"
					pc_id = decrypted_data[48:64]
					arch = decrypted_data[68:72]
					compiled_arch = decrypted_data[76:80]
					platform = decrypted_data[84:88]
					compiled_platf = decrypted_data[92:96]
					print "  PC ID: " + pc_id
					print "  Architecture: " + arch + " (" + get_arch(int(arch)) + ")"
					print "  Compiled architecture: " + compiled_arch + " (" + get_arch(int(compiled_arch)) + ")"
					print "  Platform: " + platform + " (" + get_platform(int(platform)) + ")"
					print "  Compiled platform: " + compiled_platf + " (" + get_platform(int(compiled_platf)) + ")"
					print "  Next IV: " + to_hex(IV)
					status = 3
				elif status == 4:
					# DS has sent "OS version check status" to implant
					print "packet nbr " + str(i) + ": implant acknowledges reception of OS version",
					print "check status"
					print "  Seq nbr: " + str(seq_num)
					print "  Payload length: " + str(payload_length)
					print "  Clear text length: " + str(clear_text_length)
					print "  Symm. encr. used: " + str(symm_encr_used)
					decrypted = aes_decrypt(data[8:],hex_to_bin(session_key),IV)
					print "  Decrypted data (OS version check reception acknowledgement): 0x" + to_hex(decrypted[0:clear_text_length])
					IV = data[8:]
					print "  Next IV: " + to_hex(IV)
					status = 5
				elif status == 6:
					print "packet nbr " + str(i) + ": implant asks for new command from DS"
					print "  Seq nbr: " + str(seq_num)
					print "  Payload length: " + str(payload_length)
					print "  Clear text length: " + str(clear_text_length)
					print "  Symm. encr. used: " + str(symm_encr_used)
					status = 7
				elif status == 8:
					print "packet nbr " + str(i) + ": implant acknowledges reception of File/Library info"
					print "  Seq nbr: " + str(seq_num)
					print "  Payload length: " + str(payload_length)
					print "  Clear text length: " + str(clear_text_length)
					print "  Symm. encr. used: " + str(symm_encr_used)
					decrypted = aes_decrypt(data[8:],hex_to_bin(session_key),IV)
					print "  Decrypted data (File/Library info reception acknowledgement): 0x" + to_hex(decrypted[0:clear_text_length])
					IV = data[8:]
					print "  Next IV: " + to_hex(IV)
					status = 9
				elif status == 10:
					print "packet nbr " + str(i) + ": implant acknowledges reception of Export name"
					print "  Seq nbr: " + str(seq_num)
					print "  Payload length: " + str(payload_length)
					print "  Clear text length: " + str(clear_text_length)
					print "  Symm. encr. used: " + str(symm_encr_used)
					decrypted = aes_decrypt(data[8:],hex_to_bin(session_key),IV)
					print "  Decrypted data (Export name reception acknowledgement): 0x" + to_hex(decrypted[0:clear_text_length])
					IV = data[8:]
					print "  Next IV: " + to_hex(IV)
					status = 11
		elif packets[i].payload.payload.sport == 80 or packets[i].payload.payload.sport == 443:
			payload = str(packets[i].payload.payload.payload)
			if "HTTP/1.0 200 OK" in payload:
				index = payload.index("\x0d\x0a\x0d\x0a") + 4
				data = payload[index:]
				# If the HTTP stream continues into the next packet, then append the
				# subsequent packets to the HTTP data.
				cont_length = int(re.findall("Content-Length.*",payload)[0].split(':')[1][1:])
				j = i
				while len(data) < cont_length:
					j = j + 1
					# Dirty way of checking if the next packet belongs to the same stream
					if packets[j].payload.payload.sport == 80 or packets[j].payload.payload.sport == 443:
						data = data + str(packets[j].payload.payload.payload)
				clear_text_length = 0
				payload_length = 0
				symm_encr_used = 0
				seq_num = struct.unpack('<I', data[4:8])[0]
				if (len(data) > 8):
					clear_text_length = struct.unpack('>I', data[8:12])[0]
					length2 = int(to_hex(data[12:13]),16)
					payload_length = clear_text_length + length2
					symm_encr_used = int(to_hex(data[13:14]),16)
				if status == 1:
					print "packet nbr " + str(i) + ": contains response from DanderSpritz (digital signature / magic number)"
					print "  Seq nbr: " + str(seq_num)
					print "  Payload length: " + str(payload_length)
					print "  Clear text length: " + str(clear_text_length)
					print "  Symm. encr. used: " + str(symm_encr_used)
					encrypted_data = int(to_hex(data[16:272]),16)
					decrypted_data = pow(encrypted_data,pubkey_exp_int,modulus_int)
					decrypted_data_hex = hex(decrypted_data)[2:-1]
					first_part = decrypted_data_hex[0:8]
					last_part = decrypted_data_hex[-30:]
					print "  Decrypted magic number: 0x" + first_part + "..." + last_part
					index = decrypted_data_hex.index("8e3071ab") - 8
					print "  => interpretation:"
					major_ver = int(decrypted_data_hex[index+2:index+4],16)
					minor_ver = int(decrypted_data_hex[index+6:index+8],16)
					sub_ver = int(decrypted_data_hex[index+4:index+6],16)
					print "  PeddleCheap ver: " + str(major_ver) + "." + str(minor_ver) + "." + str(sub_ver)
					print "  Magic number: " + decrypted_data_hex[index+8:index+16]
					print "  Random padding: " + decrypted_data_hex[index+16:index+20]
					print "  Nbr random bytes: " + str(int(decrypted_data_hex[index+20:],16))
					status = 2
				elif status == 3:
					# reply packet from DS to implant when symmetric key has been received by DS
					print "packet nbr " + str(i) + ": DanderSpritz response after getting magic number"
					print "  Seq nbr: " + str(seq_num)
					print "  Payload length: " + str(payload_length)
					print "  Clear text length: " + str(clear_text_length)
					print "  Symm. encr. used: " + str(symm_encr_used)

					decrypted = aes_decrypt(data[16:],hex_to_bin(session_key),IV)
					print "  Decrypted data (OS version check status): 0x" + to_hex(decrypted[0:clear_text_length])
					IV = data[16:]
					print "  Next IV: " + to_hex(IV)
					status = 4
				elif status == 5:
					if cont_length == 88:
						# In some cases it seems like DanderSpritz sends the PayloadInfo run
						# type info and File/Library info immediately after acknowledgement of
						# OS version check status. In that case, go straight to status 7.
						status = 7
					else:
						print "packet nbr " + str(i) + ": DanderSpritz empty response"
						print "  Seq nbr: " + str(seq_num)
						print "  Payload length: " + str(payload_length)
						print "  Clear text length: " + str(clear_text_length)
						print "  Symm. encr. used: " + str(symm_encr_used)
						status = 6
				if status == 7:
					print "packet nbr " + str(i) + ": DanderSpritz sends PayloadInfo run type info and",
					print "File/Library info to implant"
					print "  Seq nbr: " + str(seq_num)
					print "  Payload length: " + str(payload_length)
					print "  Clear text length: " + str(clear_text_length)
					print "  Symm. encr. used: " + str(symm_encr_used)
					decrypted = aes_decrypt(data[16:32],hex_to_bin(session_key),IV)
					IV = data[16:32]	# encrypted data is reused as an IV for the next payload in the message
					print "  Decrypted data (PayloadInfo run type info): 0x" + to_hex(decrypted[0:clear_text_length])
					print "  Next IV: " + to_hex(IV)
					clear_text_length = struct.unpack('>I', data[32:36])[0]
					length2 = int(to_hex(data[36:37]),16)
					payload_length = clear_text_length + length2
					print "  Payload length: " + str(payload_length)
					print "  Clear text length: " + str(clear_text_length)
					symm_encr_used = int(to_hex(data[37:38]),16)
					print "  Symm. encr. used: " + str(symm_encr_used)
					decrypted = aes_decrypt(data[40:],hex_to_bin(session_key),IV)
					print "  Decrypted data (File/Library info): 0x" + to_hex(decrypted[0:clear_text_length])
					IV = data[40:56]	# first 16 bytes reused as IV for next message
					print "  Next IV: " + to_hex(IV)
					status = 8
				elif status == 9:
					print "packet nbr " + str(i) + ": DanderSpritz sends Export name to implant"
					print "  Seq nbr: " + str(seq_num)
					print "  Payload length: " + str(payload_length)
					print "  Clear text length: " + str(clear_text_length)
					print "  Symm. encr. used: " + str(symm_encr_used)
					decrypted = aes_decrypt(data[16:32],hex_to_bin(session_key),IV)
					print "  Decrypted data (Export name): 0x" + to_hex(decrypted[0:clear_text_length])
					IV = data[16:]
					print "  Next IV: " + to_hex(IV)
					status = 10
				elif status == 11 or status == 12:
					print "packet nbr " + str(i) + ": DanderSpritz sends executable to implant"
					if (status == 11):
						if os.path.exists(dump_file + ".executable_encr"): os.remove(dump_file + ".executable_encr")
						print "  Seq nbr: " + str(seq_num)
						file_payload_length = payload_length
						size_of_executable = clear_text_length
						print "  Payload length: " + str(file_payload_length)
						print "  Size of executable: " + str(size_of_executable)
						print "  Symm. encr. used: " + str(symm_encr_used)
						encr_inc_size = 0
						status = 12
						encrypted_data = data[16:]
					else:
						encrypted_data = data[8:]
					encr_inc_size += len(encrypted_data)
					#print "  packet size: " + str(len(data))
					#print "  encr_inc_size: " + str(encr_inc_size)
					fp = open(dump_file + ".executable_encr","a+")
					fp.write(encrypted_data)
					fp.close()
					if encr_inc_size >= file_payload_length:
						status = 13
						print "  Encrypted executable written to " + dump_file + ".executable_encr"
						# Decrypt the encrypted file
						with open(dump_file + ".executable_encr","r") as encrfile:
							content = encrfile.read()
							decrypted = aes_decrypt(content,hex_to_bin(session_key),IV)
							fp = open(dump_file + ".executable","w")
							fp.write(decrypted[0:size_of_executable])
							fp.close()
							orig_size = struct.unpack('>I', decrypted[8:12])[0]
							print "  Original size of executable: " + str(orig_size)
						print "  Decrypted executable written to " + dump_file + ".executable"
						sys.exit(1)

