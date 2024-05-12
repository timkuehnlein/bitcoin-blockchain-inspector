# based on this: https://ultraconfig.com.au/blog/introduction-to-the-bitcoin-network-protocol-using-python-and-tcp-sockets/

# Import dependencies
import socket
import time
import random
import struct
import hashlib
import binascii

# Binary encode the network addresses
def create_network_address(ip_address, port):
    # service
    # 1	NODE_NETWORK	This node can be asked for full blocks instead of just headers.
    service = bytearray.fromhex("01")
    
    # ipv6
    # 16 byte IPv4-mapped IPv6 address (12 bytes 00 00 00 00 00 00 00 00 00 00 FF FF, followed by the 4 bytes of the IPv4 address).
    ip = bytearray.fromhex("00"*10) + bytearray.fromhex("ff"*2) + socket.inet_aton(ip_address)

    # port
    # 2 byte port number in network byte order
    port = port.to_bytes(2, byteorder='big')

    network_address = struct.pack('>8s16s2s', service, ip, port)
    return(network_address)

# Create the TCP request object
def create_message(magic, command, payload):
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
    addr_from = struct.pack('<26s', b'\x00' * 26)

    # random nonce
    nonce = random.getrandbits(64)

    # user agent
    # 0 bytes as we are not providing any user agent
    # user_agent = create_sub_version()
    user_agent = b'\x00'

    # start height, 0 as we are requesting the latest block
    start_height = 0
    # little endian (<), unsigned int (I), unsigned long long (Q), 26 byte string (26s), 26 byte string (26s), unsigned long long (Q), unsigned int (I)
    payload = struct.pack('<IQQ26s26sQ2sI', version, service, timestamp, addr_recv, addr_from, nonce, user_agent, start_height)
    return(payload)



# Create the "verack" request message
def create_message_verack():
    # just the hex dump
    return bytearray.fromhex("f9beb4d976657261636b000000000000000000005df6e0e2")




# Create the "getdata" request payload
def create_payload_getdata(tx_id):
    count = 1
    type = 1
    hash = bytearray.fromhex(tx_id)
    payload = struct.pack('<bb32s', count, type, hash)
    return(payload)



# Print request/response data
def print_response(command, request_data, response_data):
    print("")
    print("Command: " + command)
    print("Request:")
    print(binascii.hexlify(request_data))
    print("Response:")
    print(binascii.hexlify(response_data))



if __name__ == '__main__':
    # Set constants
    magic_value = 0xd9b4bef9
    tx_id = "fc57704eff327aecfadb2cf3774edc919ba69aba624b836461ce2be9c00a0c20"
    # peer_ip_address = '104.199.184.15'
    peer_ip_address = '185.197.160.61'
    peer_tcp_port = 8333
    buffer_size = 1024

    # Create Request Objects
    version_payload = create_payload_version(peer_ip_address)
    version_message = create_message(magic_value, 'version', version_payload)
    verack_message = create_message_verack()
    getdata_payload = create_payload_getdata(tx_id)
    getdata_message = create_message(magic_value, 'getdata', getdata_payload)

    # Establish TCP Connection
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((peer_ip_address, peer_tcp_port))

    # Send message "version"
    s.send(version_message)
    response_data = s.recv(buffer_size)
    print_response("version", version_message, response_data)

    # Send message "verack", no matter what the version was
    s.send(verack_message)
    response_data = s.recv(buffer_size)
    print_response("verack", verack_message, response_data)
    
    # todo spawn thread for this?
    while True:
        response_data = s.recv(buffer_size)
        print(binascii.hexlify(response_data))
        time.sleep(1)

    # Send message "getdata"
    # s.send(getdata_message)
    # response_data = s.recv(buffer_size)
    # print_response("getdata", getdata_message, response_data)

    # Close the TCP connection
    s.close()