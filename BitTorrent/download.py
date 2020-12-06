import hashlib
from message_processing import *
from bcoding import bdecode,bencode
import random
import math
import time 
from urllib.parse import urlparse
import sys
import requests
import os
import bitstring
import socket
from functions import *
from threading import Thread
from struct import pack,unpack
import ipaddress
import logging


if '-d' in sys.argv:
	SHOW_DETAILS = True

else:
	SHOW_DETAILS = False


if '-m' in sys.argv:
	try:
		MAXIMUM_PEERS = int(sys.argv[sys.argv.index('-m')+1])
	except:
		logging.error('Invalid arguments')
		sys.exit()
		
else:
	MAXIMUM_PEERS = 15
	
if '-seed' in sys.argv:
	SEEDING = True
else:
	SEEDING = False
	
	
if '-top4' in sys.argv:
	TOP_4_IS_TO_BE_USED = True
else:
	TOP_4_IS_TO_BE_USED = False	

for i in sys.argv[2:]:
	if i not in ['-d','-m','-seed','-top4']:
		try:
			i = int(i)
		except:
			logging.error('Invalid arguments')
			sys.exit()
	

DOWNLOAD_DONE = False

PEER_ID = '-AB0001-'+''.join([str(random.randint(0,9)) for _ in range(12)])

torrent = sys.argv[1]

def get_torrent_data(meta_info):
	announce = meta_info['announce']
	announce_list = meta_info['announce-list']
	try:
		comment = meta_info['comment']
	except:
		comment = None
	created_by = meta_info['created by']
	creation_date = meta_info['creation date']
	files = []
	length = 0
	root = meta_info['info']['name']
	if 'files' in meta_info['info']:
		if not os.path.exists(root):
			os.mkdir(root, 0o0766 )
		for file in meta_info['info']['files']:
			path = os.path.join(root, *file["path"])
			files.append({"path": path , "length": file["length"]})
			if not os.path.exists(os.path.dirname(path)):
				os.makedirs(os.path.dirname(path))
			files.append({"path": path , "length": file["length"]})
			length += file["length"]

	else :
		files.append({'path':meta_info['info']['name'],'length':meta_info['info']['length']})
		length = meta_info['info']['length']
	name = meta_info['info']['name']
	piece_length = meta_info['info']['piece length']
	info_hash = hashlib.sha1(bencode(meta_info['info'])).digest()
	print("announce:{}\nannounce-list:{}\ncomment:{}\ncreated by:{}\ncreation date:{}\nlength:{}\nname:{}\npiece length:{}\ninfo-hash:{}\n".format(announce,announce_list,comment,created_by,creation_date,length,name,piece_length,info_hash))
	return {'announce':announce,'announce_list':announce_list,'comment':comment,'created_by':created_by,'creation_date':creation_date,'length':length,'name':name,'piece_length':piece_length,'info_hash':info_hash,'files':files}

class Peer:
	def __init__(self,ip,port,id=None):
		self.ip = ip
		self.port = port
		self.id = id
		self.is_handshaked = False
		self.message_queue = b'' 
		self.state = {'am_choking':True,'peer_choking':True,'am_interested':False,'peer_interested':False}
		self.bitfield=None
		self.total_data_received = 0
		self.connected_on = 0.0
		self.data_supply_rate = 0.0
		

	def __str__(self):
		return "{} {} {}".format(self.ip,self.port,self.id)


class download_info:
	def __init__(self):
		self.total_size = torrent_data['length']
		self.total_chunks = math.ceil(torrent_data['length']/torrent_data['piece_length'])
		self.total_chunks_received = 0
		self.percentage = -1
		self.last_log = ""

	def show_progress(self,active_peers):
		total_data = 0
		for chunk in partitioned_chunks:
			for block in partitioned_chunks[chunk]['blocks']:
				if block['status'] == 2:
					total_data += len(block['data'])

		if total_data == self.percentage:
				return 
		peers_count = len(active_peers)
		percentage = float((float(total_data) / self.total_size) * 100)
		new_log = 'Downloading:{}% | chunks - {}/{} | peers-{}'.format(round(percentage,2),self.total_chunks_received,self.total_chunks,peers_count)
		if new_log != self.last_log :
			print(new_log)
		self.last_log = new_log
		self.percentage = percentage

def wait_for_reply(sock):
	buff = b''
	while True:
		try:
			payload = sock.recv(4096)
			if len(payload)<=0:
				break
			buff += payload
		except:
			break
	return buff


def send_udp_message(conn,sock,message):
	conn_id = message[0]
	action = message[1]
	trans_id = message[2]
	payload = message[3]
	sock.sendto(payload,conn)
	try:
		response = wait_for_reply(sock)
	except:
		print('No response')
		return

	if len(response) < len(payload):
		print('Tracker sent an incomplete message')
		#return

	if action != response[0:4] or trans_id != response[4:8]:
		print('Transaction id did not match')
		return
	return response


def try_to_connect_to_tracker(tracker_list,info_hash):
	parameters = {'info_hash': info_hash,'peer_id': PEER_ID,'port': 6885,'uploaded': 0,'downloaded': 0,'left': 0,'event': 'started'}
	#print(parameters)
	for tracker in tracker_list:

		if str.startswith(tracker[0],'http'):
			try:
				#print(tracker[0])
				print('\nTrying to connect to (HTTP) tracker -> {}'.format(tracker[0]))
				response = requests.get(tracker[0],parameters,timeout=5)
				#print(response.content,'\n')
			except:
				print('Can\'t connect to {}'.format(tracker[0]))

			if not response :
				print('No response')
				return
			response = bdecode(response.content)
			#print(response)
			peers = []
			for peer in response['peers']:
				peers.append(Peer(peer['ip'],peer['port'],peer['peer id']))
			print('Found {} peers from {}'.format(len(peers),tracker[0]))
			return peers,tracker[0]

		elif str.startswith(tracker[0],'udp'):
			print('\nTrying to connect to (UDP) tracker -> {}'.format(tracker[0]))
			request = urlparse(tracker[0])
			sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
			sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
			sock.settimeout(4)
			try:
				ip,port = socket.gethostbyname(request.hostname),request.port
			except:
				continue
			if ipaddress.ip_address(ip).is_private:
				continue
			connection_request = encode_udpconnection()
			response = send_udp_message((ip,port),sock,connection_request)
			if not response:
				print('No response for udp connection request')
				continue
			connection_response = decode_udpconnection(response)
			announce_request = encode_udpannouncerequest(connection_response[2],torrent_data['info_hash'],bytes(PEER_ID,'utf-8'))
			response = send_udp_message((ip,port),sock,announce_request)

			if not response:
				print('No response for udp announce request')
				continue

			#got list of peers
			announce_response = decode_udpannounceresponse(response)
			print('\nTracker response:\nconnection id:{}\naction:{}\ntransaction id:{}\ninterval:{}\nleechers:{}\nseeders:{}\n'.format(connection_response[2],announce_response[0],announce_response[1],announce_response[2],announce_response[3],announce_response[4]))
			peers = []
			for ip,port in announce_response[5]:
				peers.append(Peer(ip,port))
			print('Found {} peers from {}'.format(len(peers),tracker[0]))
			return peers,tracker[0]

			
with open(torrent,'rb') as f:
	meta_info = bdecode(f)


torrent_data = get_torrent_data(meta_info)

progress = download_info()

#got the chunk dictionary
chunks = get_chunks(meta_info,torrent_data['length'])

#create our bitfield
mybitfield = bitstring.BitArray(math.ceil(torrent_data['length']/meta_info['info']['piece length']))

#make partitions in chunks(form blocks)
partitioned_chunks = make_blocks_in_chunks(chunks)

#figured out which chunk goes at which place in the file
offset_map = make_download_map(partitioned_chunks,torrent_data['files'],torrent_data['piece_length'])

#got the peers
list_of_trackers,info_hash = torrent_data['announce_list'],torrent_data['info_hash']
def get_peers():
	peers,tracker = try_to_connect_to_tracker(list_of_trackers,info_hash)
	return peers,tracker

		

peer_list,tracker = get_peers()
tracker = [f'{tracker}']
list_of_trackers.remove(tracker)
print('Connecting to {}(max) peers ...'.format(MAXIMUM_PEERS))



peers_dict = {}

def connect_to_peers():
	count = 1
	for peer in peer_list:	
		try:
			sock = socket.create_connection((peer.ip,peer.port),timeout=1)
			sock.setblocking(False)
			print('{}/{} Connected to peer {}'.format(count,MAXIMUM_PEERS,peer.ip))
			peers_dict[peer]=sock
			count += 1
		except:
			print('Peer {} unreachable'.format(peer.ip))

		if count > MAXIMUM_PEERS:
			break

connect_to_peers()

#got a dictionary with peer:socket pairs
#print(peers_dict)

active_peers = {}
peer_threads = {}

def check_handshake(peer):
	try:
		handshake = decode_handshake(peer.message_queue)
		peer.message_queue=peer.message_queue[68:]
		if SHOW_DETAILS == True:
			print('Handshaked with {} successfully'.format(peer.ip))
		return True
	except:
		print('First message from {} is not handshake'.format(peer.ip))
		return False


def seperate_messages(peer):
	while len(peer.message_queue) > 4:
		if not peer.is_handshaked:
			if check_handshake(peer):
				peer.is_handshaked = True
				continue

		len_prefix = unpack('>I',peer.message_queue[:4])[0]
		message_len = len_prefix + 4
		if len(peer.message_queue) < message_len:
			break

		message = peer.message_queue[:message_len]
		peer.message_queue = peer.message_queue[message_len:]
		#print(message)
		analyzed_message = analyze_message(message)
		if analyzed_message:
			yield analyzed_message


def reply_to_peer(peer,message,sock,mybitfield=mybitfield):
	if message['type'] == 'handshake':
		pass

	elif message['type'] == 'keepalive':
		if SHOW_DETAILS == True:
			print('keepalive message from {}'.format(peer.ip))

	elif message['type'] == 'choke':
		if SHOW_DETAILS == True:
			print('choked by {}'.format(peer.ip))
		peer.state['peer_choking'] = True

	elif message['type'] == 'unchoke':
		if SHOW_DETAILS == True:
			print('unchoked by {}'.format(peer.ip))
		peer.state['peer_choking'] = False

	elif message['type'] == 'interested':
		if SHOW_DETAILS == True:
			peer.state['peer_interested'] = True
		print('peer {} is interested'.format(peer.ip))
		if peer.state['am_choking'] :
			unchoke_message = encode_unchoke()
			sock.send(unchoke_message)

	elif message['type'] == 'notinterested':
		if SHOW_DETAILS == True:
			peer.state['peer_interested'] = False
		print('peer {} is not interested'.format(peer.ip))

	elif message['type'] == 'have':
		if SHOW_DETAILS == True:
			print('peer {} has piece no {}'.format(peer.ip,message['piece_index']))
		if peer.state['peer_choking'] and peer.state['am_interested'] == False:
			tell_interested = encode_interested()
			sock.send(tell_interested)
			peer.state['am_interested'] = True

	elif message['type'] == 'bitfield':
		if SHOW_DETAILS == True:
			print('bitfield message from {}  |bitfield = {}|'.format(peer.ip,message['bitfield']))
		peer.bitfield = message['bitfield']
		if peer.state['peer_choking'] and peer.state['am_interested'] == False:
			tell_interested = encode_interested()
			sock.send(tell_interested)
			peer.state['am_interested'] = True

	elif message['type'] == 'request':
		if SHOW_DETAILS == True:
			print('peer {} is requesting piece no {}'.format(peer.ip,piece_index))
			index = message['piece_index']
			block_no = int(message['begin']/(2**14))
			data = partitioned_chunks[index]['blocks'][block_no]['data']
			chunk_msg = encode_piece(index,message['begin'],data)
			sock.send(chunk_msg)

	elif message['type'] == 'piece':
		#print(f'Piece message from {peer.ip}')
		download(message,partitioned_chunks,torrent_data['files'],offset_map,progress)
		peer.total_data_received += len(message['block'])
		mybitfield[message['index']] = True
		progress.show_progress(active_peers)

	elif message['type'] == 'cancel':
		if SHOW_DETAILS == True:
			print('cancel message from {}'.format(peer.ip))

	elif message['type'] == 'port':
		if SHOW_DETAILS == True:
			print('port message from {}'.format(peer.ip))


def receive(peer,sock):
	while not DOWNLOAD_DONE:
		try:
			data = wait_for_reply(sock)
		except:
			continue
		peer.message_queue += data
		for i in seperate_messages(peer):
			reply_to_peer(peer,i,sock)

handshake = encode_handshake(torrent_data['info_hash'],bytes(PEER_ID,'utf-8'))

progress = download_info()

for peer in peers_dict:
	try:
		peers_dict[peer].send(handshake)
		new_thread = Thread(target=receive,args=(peer,peers_dict[peer],))
		new_thread.start()
		active_peers[peer] = peers_dict[peer]
		peer_threads[peer]=new_thread
	except:
		print('Can\'t handshake with {}'.format(peer.ip))

def unchoked_peers():
	for peer in active_peers.keys():
		if peer.state['peer_choking'] == False:
			return True
	return False

def get_peer_with_chunk(index):
	peers = []
	for peer in active_peers.keys():
		if not peer.state['peer_choking'] and peer.state['am_interested'] and peer.bitfield[index]:
			peers.append(peer)
	if peers:
		return peers[random.randrange(len(peers))]
	return None


def keepalive_timer():
	while not DOWNLOAD_DONE:
		time.sleep(10)
		keepalive = encode_keepalive()
		for peer in active_peers:
			try:
				active_peers[peer].send(keepalive)
				#if SHOW_DETAILS == True:
					#print(f'Sending keep alive to {peer.ip}')
			except:
				pass


keep_alive_thread = Thread(target=keepalive_timer,args=())
keep_alive_thread.start()

def check_top_4(active_peers,peer_threads):
	data_rate = []
	top_4 = {}
	peers_sending_data = []
	for peer in active_peers:
		if peer.total_data_received:
			peers_sending_data.append(peer)

	if len(peers_sending_data) > 7:
		for peer in active_peers:
			if peer not in peers_sending_data:
				active_peers[peer].close()
				peer_threads[peer].join()
				active_peers.pop(peer)
				peer_threads.pop(peer)

	if peers_sending_data:
		for peer in peers_sending_data:
			#calculate rate at which a peer is sending data
			rate = peer.total_data_received/(time.time()-peer.connected_on)
			peer.data_supply_rate = rate
			data_rate.append(rate)

	if len(data_rate) >= 5:
		count = 0
		while data_rate and count < 4:	
			max_data = max(data_rate)		
			for peer in peers_sending_data:
				if peer.data_supply_rate == max_data:
					top_4[peer] = active_peers[peer]
					data_rate.remove(max_data)
					count += 1
		return top_4
		
	return None



def optimistic_unchoking(peer_list,active_peers,last_optimistic_unchoke_time,peer_threads):
	new_list = active_peers
	if (time.time()-last_optimistic_unchoke_time) > 10:
		for peer in peer_list:
			if peer not in active_peers:
				try:
					sock = socket.create_connection((peer.ip,peer.port),timeout=2)
					sock.setblocking(False)
					peer.connected_on = time.time()
					handshake = encode_handshake(torrent_data['info_hash'],bytes(PEER_ID,'utf-8'))
					sock.send(handshake)
					new_thread = Thread(target=receive,args=(peer,sock,))
					peer_threads[peer] = new_thread
					new_thread.start()
					new_list[peer] = sock
					print(f'Optimistically unchoked {peer.ip}')
				except:
					print(f'peer {peer.ip} is unreachable (optimistic_unchoking)')
					peer_list.remove(peer)
			if len(new_list.keys()) == 5:
				return new_list
	return None

def seeding(mybitfield,partitioned_chunks,active_peers):

	if mybitfield:
		bitfield_msg = encode_bitfield(mybitfield)
		for peer in active_peers:
			if not peer.is_handshaked:
				handshake = encode_handshake(torrent_data['info_hash'],bytes(PEER_ID,'utf-8'))
				try:
					active_peers[peer].send(handshake)
				except:
					pass
				return
			elif peer.is_handshaked and peer.state['am_choking']:
				try:
					active_peers[peer].send(bitfield_msg)
				except:
					pass
				for chunk in partitioned_chunks:
					if partitioned_chunks[chunk]['is_downloaded']:
						have_msg = encode_have(chunk)
						for peer in active_peers:
							try:
								active_peers[peer].send(have_msg)
							except:
								pass
				unchoke = encode_unchoke()
				active_peers[peer].send(unchoke)
				peer.state['am_choking'] = False
				

last_top4_checked = time.time()
last_optimistic_unchoke_time = time.time()
last_time_bitfield_have_sent = time.time()

#main loop
print('\n-  Starting Download  -\n')
while not file_download_completed(partitioned_chunks):

	if not unchoked_peers():
		time.sleep(1)
		continue

	for chunk_index in partitioned_chunks:
		if partitioned_chunks[chunk_index]['is_downloaded']:
			continue

		peer = get_peer_with_chunk(chunk_index)
		if not peer:
			continue


		check_blocks_pending_time(partitioned_chunks[chunk_index])

		remaining_blocks = get_blocks_info(partitioned_chunks[chunk_index])
		if not remaining_blocks :
			continue

		for block in remaining_blocks:
			offset=block[0]
			size = block[1]
			request = encode_request(chunk_index,offset,size)	
			try:	
				active_peers[peer].send(request)
			except:
				pass
		
		if TOP_4_IS_TO_BE_USED:
			if (time.time()-last_top4_checked) > 30:
				top4 = check_top_4(active_peers,peer_threads)
				last_top4_checked = time.time()
				if top4:
					active_peers = top4
					print('Top 4 peers:',[peer.ip for peer in active_peers])

			if len(active_peers) <= 4:
				optimistic_unchoke_list = optimistic_unchoking(peer_list,active_peers,last_optimistic_unchoke_time,peer_threads)

				if optimistic_unchoke_list:
					last_optimistic_unchoke_time = time.time()
					active_peers = optimistic_unchoke_list
					print([peer.ip for peer in active_peers])

		if SEEDING:
			if time.time() - last_time_bitfield_have_sent > 60:				
				seeding(mybitfield,partitioned_chunks,active_peers)
				last_time_bitfield_have_sent = time.time()


DOWNLOAD_DONE = True
for peer in active_peers:
	active_peers[peer].close()
for thread in peer_threads:
	peer_threads[thread].join()
keep_alive_thread.join()
print("\n-  Download complete  -\n")



