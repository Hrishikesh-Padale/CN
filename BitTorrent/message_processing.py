from struct import pack,unpack
import random
import bitstring
import socket
pstrlen = 19
pstr = b'BitTorrent protocol'

#handshake: <pstrlen><pstr><reserved><info_hash><peer_id>
def encode_handshake(info_hash,peer_id):
	handshake = pack('>B{}s8s20s20s'.format(pstrlen),pstrlen,pstr,b'\x00'*8,info_hash,peer_id)
	return handshake

def decode_handshake(payload):
	pstrlen = unpack('>B',payload[:1])[0]
	pstr = unpack('19s',payload[1:20])[0]
	reserved = unpack('8s',payload[20:28])[0]
	info_hash = unpack('20s',payload[28:48])[0]
	peer_id = unpack('20s',payload[48:68])[0]
	if pstr != b'BitTorrent protocol':
		raise ValueError('Invalid protocol identifier')
	handshake = {'type':'handshake','info_hash':info_hash,'peer_id':peer_id}
	return handshake

def encode_choke():
	choke = pack('>IB',1,0)
	return choke

def decode_choke(payload):
	len_prefix = unpack('>I',payload[:4])[0]
	ID = unpack('>B',payload[4:5])[0]
	if ID != 0:
		print("Invalid Choke message")
		return
	choke = {'type':'choke'}
	return choke

def encode_unchoke():
	unchoke = pack('>IB',1,1)
	return unchoke

def decode_unchoke(payload):
	len_prefix = unpack('>I',payload[:4])[0]
	ID = unpack('>B',payload[4:5])[0]
	if ID != 1:
		print("Invalid unchoke message")
		return
	unchoke = {'type':'unchoke'}
	return unchoke

def encode_interested():
	interested = pack('>IB',1,2)
	return interested

def decode_interested(payload):
	len_prefix = unpack('>I',payload[:4])[0]
	ID = unpack('>B',payload[4:5])[0]
	if ID != 2:
		print('Invalid interested message')
		return
	interested = {'type':'interested'}
	return interested

def encode_notinterested():
	notinterested = pack('>IB',1,3)
	return notinterested

def decode_notinterested(payload):
	len_prefix = unpack('>I',payload[:4])[0]
	ID = unpack('>B',payload[4:5])[0]
	if ID != 3:
		print('Invalid not interested message')
		return
	notinterested = {'type':'notinterested'}
	return notinterested

def encode_have(piece_index):
	have = pack('>IBI',5,4,piece_index)
	return have

def decode_have(payload):
	len_prefix = unpack('>I',payload[:4])[0]
	ID = unpack('>B',payload[4:5])[0]
	piece_index = unpack('>I',payload[5:9])[0]
	if ID != 4:
		print('Invalid Have message')
		return
	have = {'type':'have','piece_index':piece_index}
	return have

def encode_bitfield(bitfield):
	length_bitfield = len(bitfield.tobytes())
	len_prefix = 1+length_bitfield
	total_len = len_prefix + 4
	bitfield_msg = pack('>IB{}s'.format(length_bitfield),len_prefix,5,bitfield.tobytes())
	return bitfield_msg

def decode_bitfield(payload):
	len_prefix = unpack('>I',payload[:4])[0]
	ID = unpack('>B',payload[4:5])[0]
	bitfield = unpack('>{}s'.format(len_prefix-1),payload[5:5+(len_prefix-1)])[0]
	if ID != 5:
		print("Invalid bitfield message")
		return
	Bitfield={'type':'bitfield','bitfield':bitstring.BitArray(bytes(bitfield))}
	return Bitfield

def encode_keepalive():
	return pack('>I',0)

def decode_keepalive(payload):
	len_prefix = unpack('>I',payload)[0]
	if len_prefix != 0:
		print('Invalid keepalive message')
		return
	keepalive = {'type':'keepalive'}
	return keepalive

def encode_request(piece_index,begin,length):
	request = pack('>IBIII',13,6,piece_index,begin,length)
	return request

def decode_request(payload):
	len_prefix,ID,piece_index,begin,length=unpack('>IBIII',payload[:4],payload[4:5],payload[5:9],payload[9:13],payload[13:17])
	if ID != 6 :
		print('Invalid request message')
		return
	request = {'type':'request','piece_index':piece_index,'begin':begin,'length':length}
	return request

#piece: <len=0009+X><id=7><index><begin><block>
def encode_piece(index,begin,block):
	len_prefix = 9 + len(block)
	total_len = 4+len_prefix
	piece = pack('>IBII{}s'.format(len(block)),len_prefix,7,index,begin,block)
	return piece

def decode_piece(payload):
	block_len = len(payload)-13
	len_prefix,ID,index,begin,block=unpack('>IBII{}s'.format(block_len),payload[:13+block_len])
	if ID != 7:
		print('Invalid piece message')
		return None
	piece = {'type':'piece','index':index,'begin':begin,'block':block}
	return piece 

def encode_udpconnection():
	conn_id = pack('>Q', 0x41727101980)
	action = pack('>I', 0)
	trans_id = pack('>I', random.randint(0, 100000))
	return (conn_id,action,trans_id,conn_id+action+trans_id)

def decode_udpconnection(payload):
	action, = unpack('>I', payload[:4])
	trans_id, = unpack('>I', payload[4:8])
	conn_id, = unpack('>Q', payload[8:])
	return(action,trans_id,conn_id)

def encode_udpannouncerequest(conn_id,info_hash,peer_id):
	connection_id = pack('>Q', conn_id)
	action = pack('>I', 1)
	transaction_id = random.randint(0, 100000)
	trans_id = pack('>I', transaction_id)
	downloaded = pack('>Q', 0)
	left = pack('>Q', 0)
	uploaded = pack('>Q', 0)
	event = pack('>I', 0)
	ip = pack('>I', 0)
	key = pack('>I', 0)
	num_want = pack('>i', -1)
	port = pack('>h', 8000)
	msg = (connection_id + action + trans_id + info_hash + peer_id + downloaded +left + uploaded + event + ip + key + num_want + port)
	return (conn_id,action,trans_id,msg)

def get_sockets(raw_bytes):
	socks_addr = []
	for i in range(int(len(raw_bytes) / 6)):
		start = i * 6
		end = start + 6
		ip = socket.inet_ntoa(raw_bytes[start:(end - 2)])
		raw_port = raw_bytes[(end - 2):end]
		port = raw_port[1] + raw_port[0] * 256
		socks_addr.append((ip, port))
	return socks_addr

def decode_udpannounceresponse(payload):
	action, = unpack('>I', payload[:4])
	transaction_id, = unpack('>I', payload[4:8])
	interval, = unpack('>I', payload[8:12])
	leechers, = unpack('>I', payload[12:16])
	seeders, = unpack('>I', payload[16:20])
	list_sockets = get_sockets(payload[20:])
	return (action,transaction_id,interval,leechers,seeders,list_sockets)


def analyze_message(payload):

	if len(payload) == 4:
		return decode_keepalive(payload)

	ID = unpack('>B',payload[4:5])[0]
	if ID == 0:
		return decode_choke(payload)
	elif ID == 1:
		return decode_unchoke(payload)
	elif ID == 2:
		return decode_interested(payload)
	elif ID == 3:
		return decode_notinterested(payload)
	elif ID == 4:
		return decode_have(payload)
	elif ID == 5:
		return decode_bitfield(payload)
	elif ID == 6:
		return decode_request(payload)
	elif ID == 7:
		return decode_piece(payload)
	elif ID == 8:
		return {'type':'cancel'}
	elif ID == 9:
		return {'type':'port'}
	else:
		print('cant decode message')
