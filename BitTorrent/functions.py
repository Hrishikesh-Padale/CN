import math
import time
import hashlib

def get_chunks(meta_info,length):
	chunks = {}
	no_of_chunks = math.ceil(length/meta_info['info']['piece length'])
	print('Total chunks:',no_of_chunks)
	total_size = length
	chunk_size = meta_info['info']['piece length']
	pieces_hash = meta_info['info']['pieces']
	start = 0
	end = 20
	for index in range(no_of_chunks):
		if index == no_of_chunks-1:
			last_chunk_size = total_size-(chunk_size)*(no_of_chunks-1)
			chunks[index] = {'hash_value':pieces_hash[start:end],'is_downloaded':False,'blocks':[],'data':b'','size':last_chunk_size}
		else:
			chunks[index] = {'hash_value':pieces_hash[start:end],'is_downloaded':False,'blocks':[],'data':b'','size':chunk_size}
			start += 20
			end += 20 

	return chunks

def make_blocks_in_chunks(chunks):

	for chunk in chunks.values():
		#print(chunk['size'])

		total_blocks = math.ceil(chunk['size']/(2**14))
		if total_blocks > 1:
			for i in range(total_blocks):
				chunk['blocks'].append({'size':2**14,'status':0,'data':b'','pending time':0.0})
			if chunk['size'] % (2**14) != 0:
				chunk['blocks'][total_blocks-1]={'size':chunk['size']%(2**14),'status':0,'data':b'','pending time':0.0}

		else:
			chunk['blocks'].append({'size':chunk['size'],'status':0,'data':b'','pending time':0.0})

	return chunks

def make_download_map(chunk_dictionary,files,piece_length):
	offset_map = {}
	for f in files:
		piece_offset = 0
		size_of_current_file = f['length']
		while size_of_current_file>0:
			chunk_no = int(piece_offset/piece_length)
			chunk_size = chunk_dictionary[chunk_no]['size']
			if size_of_current_file - chunk_size<0:
				offset_map[chunk_no] = {'path':f['path'],'offset':piece_offset} 
				size_of_current_file = 0
			else:
				size_of_current_file -= chunk_size
				offset_map[chunk_no] = {'path':f['path'],'offset':piece_offset}
				piece_offset += chunk_size
	return offset_map



def check_blocks_pending_time(chunk):
	current_time = time.time()
	for index,block in enumerate(chunk['blocks']):
		#print(index,block)
		if block['status'] == 1 and current_time - block['pending time'] > 5:
			#print(current_time - block['pending time'] > 5)
			chunk['blocks'][index] = {'size':2**14,'status':0,'data':b'','pending time':0.0}


def get_blocks_info(chunk):
	if chunk['is_downloaded']:
		return None
	#print(index,chunk)
	remaining_blocks = []
	for index,block in enumerate(chunk['blocks']):
		#print(index,block)
		if block['status'] == 0:
			block['status'] = 1
			block['pending time'] = time.time()
			remaining_blocks.append([index*(2**14),block['size']])
	if remaining_blocks:
		return remaining_blocks
	return None

def file_download_completed(chunks):
	for chunk in chunks:
		if chunks[chunk]['is_downloaded'] == False:
			return False
	return True

def is_completed(chunk):
	for block in chunk['blocks']:
		if block['status'] == 0 or block['status'] == 1:
			return False
	return True

def write_in_file(chunk,index,file,offset_map):
	offset = offset_map[index]
	length = chunk['size']
	F = offset['path']
	piece_offset = offset['offset']
	try:
		f = open(F,'r+b')
	except:
		f = open(F,'wb')
	f.seek(piece_offset)
	f.write(chunk['data'])
	f.close()



def try_to_save_chunk(chunk,chunk_dictionary,index,files,offset_map,progress):
	data = b''
	for block in chunk['blocks']:
		data += block['data']
	data_hash = hashlib.sha1(data).digest()
	if data_hash != chunk['hash_value']:
		print('chunk no {} hash value is not matching'.format(index))
		return
	chunk['data'] = data
	chunk['is_downloaded']=True
	try :
		write_in_file(chunk,index,files,offset_map)
		#print('chunk no {} downloaded'.format(index))
		progress.total_chunks_received += 1
	except:
		print('Error while writing piece {}'.format(index))



def download(chunk_message,chunk_dictionary,files,offset_map,progress):
	chunk_index = chunk_message['index']
	offset = chunk_message['begin']
	data = chunk_message['block']
	if chunk_dictionary[chunk_index]['is_downloaded']:
		return

	block_index = int(offset/(2**14))
	if chunk_dictionary[chunk_index]['blocks'][block_index]['status'] != 2:
		chunk_dictionary[chunk_index]['blocks'][block_index]['data']=data
		chunk_dictionary[chunk_index]['blocks'][block_index]['status'] = 2
		#progress.total_data_received += len(data)

	if is_completed(chunk_dictionary[chunk_index]):
		try:
			try_to_save_chunk(chunk_dictionary[chunk_index],chunk_dictionary,chunk_index,files,offset_map,progress)
		except:
			chunk = chunk_dictionary[chunk_index]
			total_blocks = math.ceil(chunk['size']/(2**14))
			if total_blocks > 1:
				for i in range(total_blocks):
					chunk['blocks'].append({'size':2**14,'status':0,'data':b'','pending time':0.0})
				if chunk['size'] % (2**14) != 0:
					chunk['blocks'][total_blocks-1]={'size':chunk['size']%(2**14),'status':0,'data':b'','pending time':0.0}
			else:
				chunk['blocks'].append({'size':chunk['size'],'status':0,'data':b'','pending time':0.0})
			chunk_dictionary[chunk_index] = chunk
			print('Re-initialized chunk',chunk_dictionary[chunk_index])

