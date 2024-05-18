# based on this: https://ultraconfig.com.au/blog/introduction-to-the-bitcoin-network-protocol-using-python-and-tcp-sockets/

# Import dependencies
import datetime
import socket
import time
import random
import struct
import hashlib
import binascii
import threading
import winsound
import sys

class Logger(object):
    def __init__(self):
        self.terminal = sys.stdout
        self.log = open("logfile.log", "a")
   
    def write(self, message):
        self.terminal.write(message)
        self.log.write(message)  

    def flush(self):
        # this flush method is needed for python 3 compatibility.
        # this handles the flush command by doing nothing.
        # you might want to specify some extra behavior here.
        pass    

sys.stdout = Logger()


# helper to notice new block
def beep():
    try:
        frequency = 1000  # Set Frequency To 2500 Hertz
        duration = 1000  # Set Duration To 1000 ms == 1 second
        winsound.Beep(frequency, duration)
    except:
        pass
    
# helper to allow to buffer bytes that were read from the socket
# but were not needed
def reset_stream(buffer_bytes):
    global stream_buffer
    stream_buffer = buffer_bytes

# helper to read from stream or buffer
def recv(n):
    global stream_buffer
    tmp = b''
    
    if len(stream_buffer) > 0:
        if (len(stream_buffer) >= n):
            # read from buffer
            tmp = stream_buffer[:n]
            # remove the read bytes from the buffer
            stream_buffer = stream_buffer[n:]
            return tmp
        else:
            # read whole buffer
            tmp = stream_buffer
            # decrease the number of bytes to read
            n -= len(stream_buffer)
            # reset the buffer
            stream_buffer = b''
    
    # read rest from socket
    tmp = tmp + s.recv(n)
    return tmp

# helper function to read a variable length integer
def read_variable_length_integer_from_socket():
    first_byte = recv(1)[0]
    # read variable length integer
    if (first_byte < 0xfd):
        # 1 byte
        decoded_integer = first_byte
    elif (first_byte == 0xfd):
        decoded_integer = struct.unpack('<H', recv(2))[0]
    elif (first_byte == 0xfe):
        decoded_integer = struct.unpack('<I', recv(4))[0]
    else:
        decoded_integer = struct.unpack('<Q', recv(8))[0]
    
    return decoded_integer

# Binary encode the sub-version
def create_sub_version():
    sub_version = "/Satoshi:0.7.2/"
    # length of the sub-version string
    return b'\x0F' + sub_version.encode()

# Binary encode the network addresses
def create_network_address(ip_address, port):
    # service
    # 1	NODE_NETWORK	This node can be asked for full blocks instead of just headers.
    service = b'\x01'
    
    # ipv6
    # 16 byte IPv4-mapped IPv6 address (12 bytes 00 00 00 00 00 00 00 00 00 00 FF FF, followed by the 4 bytes of the IPv4 address).
    ip = bytearray.fromhex("00000000000000000000ffff") + socket.inet_aton(ip_address)

    # port
    # 2 byte port number in network byte order (unsigned short integer)

    network_address = struct.pack('>8s16sH', service, ip, port)
    return(network_address)

def read_network_address(network_address):
    (service, ip, port) = struct.unpack('>8s16sH', network_address)
    service = str(service.hex())
    ip = socket.inet_ntop(socket.AF_INET, ip[12:16])
    port = str(port)
    return(service, ip, port)

# Create the TCP request object
def create_message(magic, command, payload: bytes):
    # command
    # 12 byte string, padded with 0 bytes
    command = command.encode()
    # Calculate the checksum of the payload and take the first 4 bytes
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[0:4]
    # unsigned int (I), 12 byte string (12s), unsigned int (I), 4 byte string (4s)
    return(struct.pack('I12sI4s', magic, command, len(payload), checksum) + payload)

# Create the "version" request payload
def create_payload_version(peer_ip_address):
    # modern version
    version = 60002
    
    # service
    # 1	NODE_NETWORK	This node can be asked for full blocks instead of just headers.
    service = 1

    # timestamp in seconds
    timestamp = int(time.time())
    
    # receiver address
    addr_recv = create_network_address(peer_ip_address, 8333)

    # 26 empty bytes for addr_from
    # addr_from = struct.pack('<26s', b'\x00' * 26)
    addr_from = create_network_address("127.0.0.1", 8333)

    # random nonce
    nonce = random.getrandbits(64)

    # user agent
    user_agent = create_sub_version()
    # 0 bytes as we are not providing any user agent
    # user_agent = b'\x00'

    # start height, 0 as we are requesting the latest block
    start_height = 843699
    # little endian (<)
    payload = struct.pack(
        '<IQq26s26sQ16sL', 
        # version / unsigned int (I)
        version, 
        # service / unsigned long long (Q)
        service, 
        # timestamp / signed long (q)
        timestamp, 
        # ip / 26 byte string (26s)
        addr_recv, 
        # ip / 26 byte string (26s)
        addr_from, 
        # unsigned long (Q)
        nonce, 
        # user_agent / 16 byte string (16s)
        user_agent, 
        # start height / unsigned int (I)
        start_height)    
    return(payload)

def print_message_version(payload):
    print("############# Outgoing version message #############")
    if debug_level < 1:
        print("Message as hex: " + binascii.hexlify(payload).decode())
        (version, service, timestamp, addr_recv, addr_from, nonce, user_agent, start_height) = struct.unpack('<LQq26s26sQ16sL', payload)
        
        print("Version: " + str(version))
        print("Service: " + str(service))
        print("Timestamp: " + datetime.datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S'))
        (service, ip, port) = read_network_address(addr_recv)
        print("Addr Receiver: " + "Service: " + service + " IP: " + ip + " Port: " + port)
        (service, ip, port) = read_network_address(addr_from)
        print("Addr From: " + "Service: " + service + " IP: " + ip + " Port: " + port)
        print("Nonce: " + str(nonce))
        print("User Agent: " + str(user_agent))
        print("Start Height: " + str(start_height))


# Create the "verack" request message
def create_message_verack():
    # just the hex dump
    return bytearray.fromhex("f9beb4d976657261636b000000000000000000005df6e0e2")

# Print the "verack" payload
def print_message(msg: bytes, incoming = True):
    global current_block_hash
    
    if (len(msg) == 0):
        print("\nNo data received")
        return
    
    print("")
    if incoming:
        print("############# Incoming message #############")
    else:
        print("############# Outgoing message #############")
    
    if debug_level < 1:
        print("Message as hex: " + binascii.hexlify(msg).decode())
        print("Message length: " + str(len(msg)))
    
    (magic_value, command, payload_length, checksum) = struct.unpack('I12sI4s', msg[0:24])
    
    command_string = command.decode().replace("\x00", "")
    print("Command: " + command_string)
    
    if debug_level < 1:
        print("Magic Value: " + hex(magic_value))
        print("Payload Length: " + str(payload_length))
        print("Checksum: " + binascii.hexlify(checksum).decode())
    
    if(payload_length > 0 and "block" not in command_string):
        if(incoming):
            payload = recv(payload_length)
        else:
            payload = msg[24:]
            
        # skip invs
        # if ("inv" in command_string):
        #     return
        
        if debug_level < 1:
            print("Payload: " + binascii.hexlify(payload).decode())
            sha256 = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[0:4]
            print("Checksum calculated: " + binascii.hexlify(sha256).decode())
        
            if("alert" in command_string or "reject" in command_string):
                print(str(payload))
            
            if("getdata" in command_string):
                parse_and_print_inv_payload(payload)
        
        if("inv" in command_string):
            inv_list = parse_and_print_inv_payload(payload)
            for (type_int, hash_bytes) in inv_list:
                # only interested in blocks
                if (type_int == 2):
                    current_block_hash = hash_bytes
                    handle_tx(binascii.hexlify(hash_bytes).decode())
            
    # block payload
    if("block" in command_string):
        beep()
        payload = recv(80)
        print(f"Block payload, first 80 bytes: {binascii.hexlify(payload[0:80]).decode()}")
        sha256 = hashlib.sha256(hashlib.sha256(payload[0:80]).digest()).digest()
        current_block_hash_string = binascii.hexlify(current_block_hash).decode()
        calculated_hash_string = binascii.hexlify(sha256).decode()
        print(f"Block Hash: {current_block_hash_string}")
        print(f"Hash calculated: {calculated_hash_string}")
        same = current_block_hash_string == calculated_hash_string
        print(f"Hashes are the same: {same}")
        print_block_header(payload[0:80])
        
        # at most 8 bytes
        num = read_variable_length_integer_from_socket()
        print(f'txn_count: {num}')
        
        value = 0
        for i in range(num):
            print(f'#### transaction {i} ####')
            value += print_transaction()
            
        print('# total block value: {:0.8f}'.format(value))


# BLOCK PAYLOAD
# Field Size    Description	    Data type   Comments
# 4	            version	        int32_t     Block version information (note, this is signed)
# 32	        prev_block	    char[32]	The hash value of the previous block this particular block references
# 32	        merkle_root	    char[32]	The reference to a Merkle tree collection which is a hash of all transactions related to this block
# 4	            timestamp	    uint32_t	A Unix timestamp recording when this block was created (Currently limited to dates before the year 2106!)
# 4	            bits	        uint32_t	The calculated difficulty target being used for this block
# 4	            nonce	        uint32_t	The nonce used to generate this block… to allow variations of the header and compute different hashes
# 1+	        txn_count	    var_int	    Number of transaction entries
#  ?	        txns	        tx[]	    Block transactions, in format of "tx" command
def print_block_header(payload: bytes):
    (version, prev_block, merkle_root, timestamp, bits, nonce) = struct.unpack('<i32s32sIII', payload[0:80])
    print(f'version: {version}')
    print(f'prev_block hash: {prev_block.hex()}')
    print(f'merkle_root: {merkle_root.hex()}')
    print(f'timestamp: {datetime.datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')}')
    print(f'bits difficulty target: {bits}')
    print(f'nonce: {nonce}')

# transaction
# Field Size	Description     Data type	    Comments
# 4	            version	        uint32_t	    Transaction data format version
# 0 or 2	    flag	        optional        uint8_t[2]	If present, always 0001, and indicates the presence of witness data
# 1+	        tx_in count	    var_int	        Number of Transaction inputs (never zero)
# 41+	        tx_in	        tx_in[]	        A list of 1 or more transaction inputs or sources for coins
# 1+	        tx_out count    var_int	        Number of Transaction outputs
# 9+	        tx_out	        tx_out[]	    A list of 1 or more transaction outputs or destinations for coins
# 0+	        tx_witnesses	tx_witness[]	A list of witnesses, one for each input; omitted if flag is omitted above
# 4	            lock_time	    uint32_t	    The block number or timestamp at which this transaction is unlocked:
def print_transaction():
    # version
    version = struct.unpack('<I', recv(4))[0]
    print(f'version: {version}')
    # flag
    flag = recv(2)
    witnesses = False
    if (flag == b'0001'):
        witnesses = True
        print(f'flag: {flag.hex()} / witnesses')
    else:
        print('flag: no witnesses')
        reset_stream(flag)
    # tx_in count
    tx_in_count = read_variable_length_integer_from_socket()
    print(f'tx_in count: {tx_in_count}')
    # skip tx_in
    for _ in range(tx_in_count):
        skip_tx_in()
    # tx_out count
    tx_out_count = read_variable_length_integer_from_socket()
    print(f'tx_out count: {tx_out_count}')
    value = 0
    for _ in range(tx_out_count):
        value += read_and_print_tx_out()
    
    print('# total transaction value: {:0.8f}'.format(value))
    
    if witnesses:
        witness_count = read_variable_length_integer_from_socket()
        print(f'witness count: {witness_count}')
        for _ in range(witness_count):
            witness_data_length = read_variable_length_integer_from_socket()
            _ = recv(witness_data_length)
    
    # skip lock time
    _ = recv(4)
    return value
    
def read_and_print_tx_out():
    # value
    value = struct.unpack('<Q', recv(8))[0]
    value = value / 100000000
    print('value: {:0.8f}'.format(value))
    # script length
    script_length = read_variable_length_integer_from_socket()
    # skip script
    _ = recv(script_length)
    return value
        
def skip_tx_in():
    # skip previous_output
    _ = recv(36)
    # script length
    script_length = read_variable_length_integer_from_socket()
    # skip script
    _ = recv(script_length)
    # skip sequence
    _ = recv(4)
    
# Create the "getdata" request payload
def create_payload_getdata(tx_id):
    count = 1
    # only interested in blocks
    type = 2
    hash = bytearray.fromhex(tx_id)
    # payload = struct.pack('<bb32s', count, type, hash)
    # return(payload)
    
    payload = struct.pack('<bI32s', count, type, hash)
    return payload

# helper function to print inv payload
def parse_and_print_inv_payload(payload: bytes):
    # read inv message
    (count, initial_offset) = read_variable_length_integer(payload)
    
    if debug_level < 1:
        print("Count: " + str(count))
    
    hash_list: list[int, str] = []
    
    for i in range(count):
        offset = initial_offset + i * 36
        if (offset + 36 > len(payload)):
            break
        
        type_integer: int = struct.unpack('<I', payload[offset:(offset + 4)])[0]
        hash_bytes: bytes = payload[(offset + 4):(offset + 4 + 36)]
        hash_string: str = binascii.hexlify(hash_bytes).decode()
        
        if debug_level < 1:
            match type_integer:
                case 1:
                    print("Type: MSG_TX " + str(type_integer))
                case 2:
                    print("Type: MSG_BLOCK " + str(type_integer))
                case 3:
                    print("Type: MSG_FILTERED_BLOCK " + str(type_integer))
                case 4:
                    print("Type: MSG_CMPCT_BLOCK " + str(type_integer))
                case _:
                    print("Type: " + str(type_integer))
            print("Hash: " + hash_string)
            
        hash_list.append((type_integer, hash_bytes))
        
    return hash_list

def handle_tx(tx_id: str):
    print("\n\n\nHandling tx: " + tx_id)
    getdata_payload = create_payload_getdata(tx_id)
    getdata_message = create_message(magic_value, 'getdata', getdata_payload)
    s.send(getdata_message)
    print_message(getdata_message, False)
    response_data = recv(buffer_size)
    print_message(response_data)

# helper function to read a variable length integer
def read_variable_length_integer(payload: bytes):
    print(f'payload: {binascii.hexlify(payload)}')
    # read variable length integer
    if (payload[0] < 0xfd):
        # 1 byte
        decoded_integer = payload[0]
        initial_offset = 1
    elif (payload[0] == 0xfd):
        decoded_integer = struct.unpack('<H', payload[1:3])[0]
        initial_offset = 3
    elif (payload[0] == 0xfe):
        decoded_integer = struct.unpack('<I', payload[1:5])[0]
        initial_offset = 5
    else:
        decoded_integer = struct.unpack('<Q', payload[1:9])[0]
        initial_offset = 9
    
    return (decoded_integer, initial_offset)

if __name__ == '__main__':
    global stream_buffer
    stream_buffer = b''
    
    global current_block_hash
    current_block_hash = b''
    
    # print_message(binascii.unhexlify(test), False)
    
    # test inv payload
    # test = b'0201000000c06862f7e66a0dfe70aee074c5b76f23bf4f9d39a7bdeac014c3843e195ddddd01000000b3f8708ed24122346d6b52aec7c4ad90b099659327230122e3ec5e38330a2e4e'
    # payload = binascii.unhexlify(test)
    
    # break
    # struct.unpack('<I', payload[0:1])
    
    
    
    # Start a new thread that listens for user input
    # stop_reading = False
    # threading.Thread(target=user_input_listener).start()

    # Set constants
    magic_value = 0xd9b4bef9
    # tx_id = "fc57704eff327aecfadb2cf3774edc919ba69aba624b836461ce2be9c00a0c20"
    # tx_id = "00000000000000000001caa3f3b70e7de9aeca10de166dde897ad4f1004b9864"
    tx_id = "307ebb3d195b9dfc6da879ad7ad8dc0d9582962cb2bb8bbeb0ac7e5031f0a68d01000000"
    # peer_ip_address = '104.199.184.15'
    peer_ip_address = '185.197.160.61'
    # peer_ip_address = '51.195.28.51'
    peer_tcp_port = 8333
    buffer_size = 24
    
    
    global debug_level
    debug_level = 0

    # Create Request Objects
    version_payload = create_payload_version(peer_ip_address)
    version_message = create_message(magic_value, 'version', version_payload)
    verack_message = create_message_verack()
    # getdata_payload = create_payload_getdata(tx_id)
    # getdata_message = create_message(magic_value, 'getdata', getdata_payload)

    # Establish TCP Connection
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(60)
    print("Socket timeout: " + str(s.timeout))
    # struct.unpack("<III", '')
    s.connect((peer_ip_address, peer_tcp_port))

    # Send message "version"
    s.send(version_message)
    print_message_version(version_payload)
    response_data = recv(buffer_size)
    print_message(response_data)    

    # Send message "verack", no matter what the version was
    s.send(verack_message)
    print_message(verack_message, False)
    response_data = recv(buffer_size)
    print_message(response_data)
    
    
    # todo spawn thread for this?
    # while True:
    #     response_data = recv(buffer_size)
    #     print(binascii.hexlify(response_data))
    #     time.sleep(1)
    
    # s.send(getdata_message)
    # print_message(getdata_message, False)
    
    # read whatever is coming in
    try:
        while True:
            time.sleep(3)
            response_data = recv(buffer_size)
            print_message(response_data)
    except KeyboardInterrupt:
        print("KeyboardInterrupt")
        pass
    
    # Send message "getdata"
    # s.send(getdata_message)
    # print_message(getdata_message, False)
    # response_data = recv(buffer_size)
    # print_message(response_data)
    
    # while not stop_reading:
    #     time.sleep(1)
    #     response_data = recv(buffer_size)
    #     print_message(response_data)

    # Close the TCP connection
    s.close()