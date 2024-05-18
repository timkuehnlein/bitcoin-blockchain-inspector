The application displays blocks as they are mined by the Bitcoin system. For each block, it displays:
* The date and time that the block was added to the blockchain, formatted in a human readable form (e.g. 1st April 2024 at 20:40)
* A list of the transactions in the block, and the value of each transaction
* The nonce that was used to successfully hash the block, and the difficulty level
* Verify that that hash does indeed match the hash included in the block

# Bitcoin transactions
You can read about the Bitcoin transaction format here:
https://en.bitcoin.it/wiki/Protocol_documentation
The basic gist is all messages sent over the network use a specific datagram format, consisting of:
* The magic number 0xD9B4BEF9, encoded in little endian format, i.e. as 0xF9BEB4D9
* 12 bytes, indicating the type or (command) of transaction being send, with zeros as padding at the end if the type is less than 12 bytes long
* The length of the payload in bytes, encoded as a 32-bit value
* A checksum, the first four bytes of the double SHA256 hash of the payload (the double SHA256 of a value is the SHA256 of the SHA256 of this value!)
* The payload itself
The website contains detailed information about the encoding of each of the payloads that can be 
used in the payload field.

# Codebase architecture

just the python cmd script :)

# Example output

example.log and example2.log show an example output of the script, with the notable fields highlighted below:

```
############# Incoming message #############
Message as hex: f9beb4d9626c6f636b0000000000000036590c00159cb2e3
Message length: 24
Command: block
Magic Value: 0xd9b4bef9
Payload Length: 809270
Checksum: 159cb2e3
Block payload, first 80 bytes: 0080032d83b43455978ab36c57e184dcfcf92ce70cf8e83327a90200000000000000000048b8dac3f831c2b4e962aa42463f952cc028f370eab9e4f629e6c88e1c66dcc65af347669a62031759422267
Block Hash: 38a325a457f93b4de8021090dee4c0397de10dc9d5bf01000000000000000000
Hash calculated: 38a325a457f93b4de8021090dee4c0397de10dc9d5bf01000000000000000000
Hashes are the same: True  <----------- validate hash
version: 755204096
prev_block hash: 83b43455978ab36c57e184dcfcf92ce70cf8e83327a902000000000000000000
merkle_root: 48b8dac3f831c2b4e962aa42463f952cc028f370eab9e4f629e6c88e1c66dcc6
timestamp: 2024-05-18 01:16:26 <--------------- readable timestamp
bits difficulty target: 386097818 <---------------- difficulty target
nonce: 1730298457 <---------------- solution nonce
txn_count: 5256
#### transaction 0 #### <------------ list of all transactions with values
version: 1
flag: no witnesses
tx_in count: 1
tx_out count: 5
value: 0.00000546
value: 3.25482119
value: 0.00000000
value: 0.00000000
value: 0.00000000
# total transaction value: 3.25482665
#### transaction 1 ####
...
#### transaction 5255 ####
version: 2
flag: no witnesses
tx_in count: 1
tx_out count: 2
value: 0.00003759
value: 0.00000000
# total transaction value: 0.00003759
# total block value: 20794.57417803  <------- total block value counted up
```

# Installation

Python required: https://www.python.org/downloads/

# Running

`python .\python.py` runs the script.

Its output is written to the console and to a log file `logfile.log` (appended).

# Thoughts

## Reading bytes
As messages come in, the header is read from the socket and parsed. Then, the payload length is read from the stream and parsed, if necessary.

As the blocks have very large payloads, only field by field is read from the stream. If an optional field is being read and turns out not to be there, those bytes are written to a buffer. When the next bunch of bytes need to be read from the socket, first the buffer is checked and read, then the socket.

## Structure of the Script

There is no structure. The main script creates a socket and does the initial handshake with the server. Then it waits for incoming messages and prints them. Details are implemented as functions.

## Weakness

Sometimes after doing the handshake and getting some initial messages, like addr, the socket is closed (seen as [FIN] in Wireshark). Then the script prints "No data received" in a loop. Restarting often helps. Just give it a couple of retries. Patience.

## Winux

Tested on Windows and Linux (only beeps on Windows for new blocks)