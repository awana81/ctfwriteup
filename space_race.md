# Challenge Overview
The Space Race challenge required finding a flaw in the flight control software that communicated with the a comms service binary provided only the comms service binary. The binary provided was a 2MB+ stripped ELF64 file.

# Analysis
Strings in the provided binary made it clear that the binary was written in rust. As such, it was unlikely that the flaw was a memory corruption, and given the name of the program, we guessed that a race condition of some sort was the goal.
