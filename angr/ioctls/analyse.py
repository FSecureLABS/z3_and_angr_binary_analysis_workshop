import angr
import pyvex
import claripy
import sys

if len(sys.argv) < 2:
	print('Usage: python analyse.py $PATH_TO_DRIVER')
	sys.exit(1)

# Load target driver
p = angr.Project(sys.argv[1],load_options={"auto_load_libs":False})

# Dissassemble the driver and lift to VEX
cfg = p.analyses.CFGFast()
all_vex = [p.factory.block(i.addr).vex for i in cfg.nodes()]

# Attempt to find the dispatch function based on the knowledge of it 
# being loaded at an offset of 0x70 in the driver structure
dispatch_addr = None
const_seen = False
for vex in all_vex:
    for stmt in vex.statements:
        const = stmt.constants
        if len(const) > 0:
            if const[0].value == 0x70:
                const_seen = True
        if isinstance(stmt, pyvex.IRStmt.IMark):
            const_seen = False
        if isinstance(stmt, pyvex.IRStmt.Store) and const_seen:
            store_consts = stmt.constants
            if len(store_consts) > 0:
                dispatch_addr = store_consts[0].value
                break
if not dispatch_addr:
    print("Could not find IOCTL dispatch function :(")  
    sys.exit(1)

print("Dispatch function found: {}".format(hex(dispatch_addr)))
# Use symbolic execution starting at the begginning of the dispatch function

s = p.factory.blank_state(addr=dispatch_addr)
pg = p.factory.simulation_manager(s)

# Ranges the image has been mapped into memory by angr
min_image_addr = p.loader.main_object.min_addr
max_image_addr = p.loader.main_object.max_addr

generic_reg_vals = set()
val_addr = {}
steps = 0
default_regs = ['eax', 'ecx', 'edx', 'ebx', 'esi', 'edi']
# As long as there's any valid path active, symbolicaly execute a single instruction
# Then save the values of all the general purpose registers
while len(pg.active) > 0 and steps < 25:
	for i in pg.active:
		print('step: {}, addr: {}'.format(steps, hex(i.addr)))
		# Skip bad addresses
		if i.addr < min_image_addr or i.addr > max_image_addr:
			print('Path has entered invalid address range, skipping')
			continue
		for reg in default_regs:
			try:
				val = i.solver.eval(getattr(i.regs, reg))
				# Always use first occurrence of a value
				# All the IOCTL code values should be solvable by angr
				# as they require comarison to constant values or entries in jump tables, etc
				generic_reg_vals.add(val)
				if val not in val_addr:
					val_addr[val] = i.addr
			except angr.errors.SimUnsatError:
				print("failed to get {}".format(reg))
			except claripy.errors.ClaripyZeroDivisionError:
				print("failed to get {}".format(reg))
	pg.step()
	steps += 1
device_codes = {}
# filter all the register values based on the device code portion of an IOCTL code
generic_reg_vals = list(filter(lambda x: 0xfff0 > ((x >> 16) & 0xffff) > 0x10, generic_reg_vals))
for i in generic_reg_vals:
	try:
		device_codes[((i >> 16) & 0xffff)] += 1
	except:
		device_codes[((i >> 16) & 0xffff)] = 1

if len(device_codes.keys()) == 0:
	print('No likely device codes found, giving up!')
	sys.exit(1)

# The device code *should* be the same for all supported IOCTL codes
print('potential device codes: {}'.format(device_codes))
likely_device_code = max(device_codes, key=device_codes.get)
print("Likely device code: {}".format(hex(likely_device_code)))

# Go through all potential values and print everything with a matching device code portion
out = []
for i in generic_reg_vals:	
	addr = val_addr[i]
	if (i >> 16) & 0xffff == likely_device_code:
		print("IOCTL code: {}".format(hex(i)))
