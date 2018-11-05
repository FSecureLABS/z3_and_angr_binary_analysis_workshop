# Intro to Binary Analysis with Z3 and Angr

Originally delivered by Sam Brown at Steelcon and hack.lu 2018, this was a three hour workshop introducing attendees to using Z3 and Angr for binary analysis. The workshop provided an introduction to SMT solvers, the Z3 SMT solver and its python library and the Angr binary analysis framework.

Through out the workshop exercises were provided which aimed to demonstrate potential applications of the technology to assist security researchers in carrying out reverse engineering and vulnerability research.

The slides provide a rough guide for the content and what order to try the exercises in. 

## Examples and Exercises

### Z3

| Name | Type | Description |
|------|------|-------------|
| [N Queens](https://github.com/sam-b/z3_and_angr_binary_analysis_workshop/tree/master/z3/n_queens) | Example | 'How can N queens be placed on an NxN chessboard so that no two of them attack each other?' Uses Z3 to generate solutions for an N * N chessboard|
| [Hackvent 15](https://github.com/sam-b/z3_and_angr_binary_analysis_workshop/tree/master/z3/hackvent_15) | Example | Solution and walk through for solving a Hackvent 15 CTF challenge with Z3 |
| [Suduko](https://github.com/sam-b/z3_and_angr_binary_analysis_workshop/tree/master/z3/suduko) | Exercise | Try to solve Suduko using Z3 |
| [RNG](https://github.com/sam-b/z3_and_angr_binary_analysis_workshop/tree/master/z3/rng) | Exercise | Optional exercises - using Z3 to find non-cryptographically secure random number generators seed value |
| [x86](https://github.com/sam-b/z3_and_angr_binary_analysis_workshop/tree/master/z3/x86) | 50/50 | Half examples, half DIY - implement simiplified versions of x86 instructions using Z3 |
|[Opaque Predicates](https://github.com/sam-b/z3_and_angr_binary_analysis_workshop/tree/master/z3/opaque_predicates)| Exercise | Use the instructions implemented previously to identify [Opaque Predicates](https://en.wikipedia.org/wiki/Opaque_predicate) in small sequences of assembly instructions |
|[Equivalence Checking](https://github.com/sam-b/z3_and_angr_binary_analysis_workshop/tree/master/z3/equivalence_checking)| Example | Use the instructions implemented previously to identify equivalent sequences of instructions |
### Angr
| Name | Type | Description |
|------|------|-------------|
| [opaque_predicates](https://github.com/sam-b/z3_and_angr_binary_analysis_workshop/tree/master/angr/opaque_predicates)| Example | Using Angr to identify opaque predicates with much less work :) |
| [IOCTLs](https://github.com/sam-b/z3_and_angr_binary_analysis_workshop/tree/master/angr/ioctls)| Example | Identify Windows driver [IOCTL codes](https://docs.microsoft.com/en-us/windows/desktop/devio/device-input-and-output-control-ioctl-) using Angr |
| [Hello World](https://github.com/sam-b/z3_and_angr_binary_analysis_workshop/tree/master/angr/hello_world)| 50/50 | Exercise and walkthrough on using Angr to generate valid arguments for a simple 'License Key Validator' |
| [Bomb Lab](https://github.com/sam-b/z3_and_angr_binary_analysis_workshop/tree/master/angr/bomb_lab)| Exercise | DIY exercise using Angr to solve a 'Bomb lab' |

## Setup

All code is in Python3 and you should only need to install the [Angr](http://angr.io/) binary analysis framework.

```
mkvirtualenv --python=$(which python3) angr && python -m pip install angr
workon angr 
```
