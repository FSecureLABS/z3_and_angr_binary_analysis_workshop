# Road Rage

## What even

This uses some dirty scripting combined with the [Angr](http://angr.horse) binary analysis framework to discover valid IOCTLs for Windows drivers. First it finds the drivers dispatch table using some dirty educated guesswork, then it symbolically executes from the disptach tables entry point until all the paths have been deadended or errored out. While it's executing it saves all the potential values for the general purpose registers and once complete uses some basic heuristics to discover potential IOCTL codes.

This won't work on drivers compiled with the latest WDK but I tested on a bunch of drivers from OEM's/AV firms and it worked on what I tried it on. 
