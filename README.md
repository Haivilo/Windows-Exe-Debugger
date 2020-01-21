# Win EXE Dubugger

This is the sample executable debugger I made

## Usage

```
bp + adress : INT3 Breakpoint
mme + adress : Memory exe Breakpoint
mmr + adress : Memory read Breakpoint
mmw + adress : Memory write Breakpoint
hd + adress : Hardware Breakpoint
hdrw + adress : Hardware rw Breakpoint
hdw + adress : hardware w Breakpoint
g : run
r : read registers
t : step in
tt : step over
eax/ebx/ecx/edx, etc. + value : change register value
ss : check stack
dump : dump the executable
module : print module
readmem + address : read memory
writemem + address : write memory
```

