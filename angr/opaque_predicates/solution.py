import angr
import archinfo

# Sample opcode sequences we wish to analyze
traces = [
    b"\x31\xC0\x0F\x80\x01\x00\x00\x00", # 0x0: xor   eax, eax 0x2:    jo  9
    b"\x31\xC0\x0F\x84\x01\x00\x00\x00", # 0x0:  xor eax, eax 0x2:    je  9
    b"\x31\xD8\x0F\x84\x01\x00\x00\x00", # 0x0:  xor eax, ebx 0x2:    je  9
    b"\x25\xff\xff\xff\x3f\x81\xe3\xff\xff\xff\x3f\x31\xd1\x31\xfa\x01\xd8\x0f\x80\x10\x00\x00\x00", 
    # 0x0:  and eax, 0x3fffffff 0x5:    and ebx, 0x3fffffff 0xb:    xor ecx, edx 0xd:    xor edx, edi 0xf:    add eax, ebx 0x11:   jo  0x27
    b"\x25\xff\xff\xff\x3f\x81\xe3\xff\xff\xff\x3f\x31\xd1\x31\xfa\x31\xD8\x0F\x84\x10\x00\x00\x00" 
    # 0x0:  and eax, 0x3fffffff 0x5:    and ebx, 0x3fffffff 0xb:    xor ecx, edx 0xd:    xor edx, edi 0xf:    xor eax, ebx 0x11:   je  0x27
]


def test_for_opaque_predicate(trace):

    # Generally we use angr to load ull binaries into memory but this method allows us to load a shellcode sample
    p = angr.project.load_shellcode(trace, archinfo.ArchX86) 
    # We start with zero program state, all registers are symbolic and the only concrete values are that EIP 
    # points to the start of our shellcode
    s = p.factory.blank_state()
    pg = p.factory.simulation_manager(s)
    # Run the code until all paths have errored or the full shellcode has ran
    out =  pg.run()
    # Pretty Print the dissasembly of the shellcode
    p.factory.block(0).capstone.pp()
    # If there's only a single path in the shellcode then the conditional branch each sample ends with can't possibly
    # be executed
    if len(out.errored) == 1:
        return True #Only one path - must be an opaque predicate
    # If there's potentially multiple paths make the path state concrete to ensure
    # they're all definitely possible paths
    sat_paths = 0
    for i in out.errored:
        if i.state.satisfiable():
            sat_paths +=1
    if sat_paths > 1:
        return False #multiple valid paths, jmp must be optional
    return True #Only one achievable path

if __name__ == "__main__":
    for t in traces:
        if test_for_opaque_predicate(t):
            print("Opaque predicate")
        else:
            print("Not an opaque predicate")

"""

Detects opaque predicates in single basic blocks, see: http://zubcic.re/blog/experimenting-with-z3-proving-opaque-predicates and https://github.com/JonathanSalwan/Triton/blob/master/src/examples/python/proving_opaque_predicates.py

Sample output:

(angr)sam@angr-dev:~/code/opaque_predicates$ python test.py 
WARNING | 2016-08-20 21:13:33,412 | angr.path_group | No completion state defined for path group; stepping until all paths deadend
0x0:    xor eax, eax
0x2:    jo  9
opaque predicate
WARNING | 2016-08-20 21:13:34,975 | angr.path_group | No completion state defined for path group; stepping until all paths deadend
0x0:    xor eax, eax
0x2:    je  9
opaque predicate
WARNING | 2016-08-20 21:13:36,648 | angr.path_group | No completion state defined for path group; stepping until all paths deadend
0x0:    xor eax, ebx
0x2:    je  9
not an opaque predicate
WARNING | 2016-08-20 21:13:37,933 | angr.path_group | No completion state defined for path group; stepping until all paths deadend
0x0:    and eax, 0x3fffffff
0x5:    and ebx, 0x3fffffff
0xb:    xor ecx, edx
0xd:    xor edx, edi
0xf:    add eax, ebx
0x11:   jo  0x27
opaque predicate
WARNING | 2016-08-20 21:13:39,450 | angr.path_group | No completion state defined for path group; stepping until all paths deadend
0x0:    and eax, 0x3fffffff
0x5:    and ebx, 0x3fffffff
0xb:    xor ecx, edx
0xd:    xor edx, edi
0xf:    xor eax, ebx
0x11:   je  0x27
not an opaque predicate
"""
