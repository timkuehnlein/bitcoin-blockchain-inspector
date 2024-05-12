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

todo