# Challenge Overview
The Space Race challenge required finding a flaw in the flight control software that communicated with the a comms service binary provided only the comms service binary. The binary provided was a 2MB+ stripped ELF64 file.

# Analysis
Strings in the provided binary made it clear that the binary was written in rust. As such, it was unlikely that the flaw was a memory corruption, and given the name of the program, we guessed that a race condition of some sort was the goal. This binary is large so we started with looking at where data is processed from "recv" functions along with strings.

Strings are not null terminated in the rust binary making, instead stored as a count and pointer, with the strings occuring one after another making it harder to analyze the individual ones. Looking for flag showed several strings related to a flag process, showing that there are options to start, stop, and request the flag from the flag process. Further the start and stop required an authorization key. Tracing what the value was for the authorization appeared to show that it came from a configuration file, so we could not grab it from the binary.

We created structures in IDA Pro to be able to follow buffers and strings in the rust program, as we were not terribly famililar with the rust API that would be represented by the compiled code. We also looked at the places where recv was called to see how our data was processed. One of the location added to a buffer and was located close the same function that appeared to parse and use the data before accessing the flag process. Tracing functions and the use of the recv'ed buffer showed two helpful points:
1. The data was immediately passed into a CRC32 function that checked the data against the last four bytes of the message
2. One built a message four output that did a lot of bit twiddling. We decided to use this information to attempt to parse the messages received from the service.

# Final Solution
