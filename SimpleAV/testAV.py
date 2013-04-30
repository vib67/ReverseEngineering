
import os, sys
import array
sys.path.append("..")
sys.path.append("../lib")
import pydasm
import pefile
from PyEmu import PEPyEmu
import string

def SearchString(text, pattern, no_of_split):
	
	patterns=pattern.split("*", no_of_split)
	
	for  pattern in patterns:
		
		offset = text.find(pattern)
		if(offset == -1):
			print "not found"  ,hex(ord(pattern[0])), offset
			return 0 
		text= text[offset+len(pattern):]

	return 1


def findObsSignature(filename):
	
	
	if filename:
    		pe = pefile.PE(filename)
	else:
   		print "[!] Blank filename specified"
    		sys.exit(2)
	
	imagebase = pe.OPTIONAL_HEADER.ImageBase
	codebase = pe.OPTIONAL_HEADER.ImageBase + pe.OPTIONAL_HEADER.BaseOfCode
	database = pe.OPTIONAL_HEADER.ImageBase + pe.OPTIONAL_HEADER.BaseOfData
	entrypoint = pe.OPTIONAL_HEADER.ImageBase + pe.OPTIONAL_HEADER.AddressOfEntryPoint
	print "[*] Image Base Addr:  0x%08x" % (imagebase)
	print "[*] Code Base Addr:   0x%08x" % (codebase)
	print "[*] Data Base Addr:   0x%08x" % (database)
	print "[*] Entry Point Addr: 0x%08x\n" % (entrypoint)
	ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
	ep_ava = ep+pe.OPTIONAL_HEADER.ImageBase
	data = pe.get_memory_mapped_image()[ep:ep+40]
	
	offset=0
	#idata = array.array('B', [0xb9,0x5a,0x01,0x00,0x00,0x43,0x4b,0xbe,0x00,0x10,0x40,0x00,0xb3,0xa6,0x8a,0x16,0x32,0xd3])
	idata = array.array('B', [0xB9,0x2A,0xBE,0x2A,0xB3,0x2A,0x8A,0x16,0x32,0xD3,0x8A,0x1E,0x88,0x16,0x46,0xE2,0x2A,0xE9])
	signature = idata.tostring()
	#ret= data.find(data,signature,4)
	ret=  SearchString(data,signature,5)
	print "Signature " ,ret
	emu = PEPyEmu()
	#emu.debug(1)
	for section in pe.sections:
		if section.Name.startswith(".text"):
        		textsection = section
    		elif section.Name.startswith(".rdata"):
        		datasection = section
	for x in range(len(textsection.data)):
	    c = textsection.data[x]
	    emu.set_memory(codebase + x, int(ord(c)), size=1)
	for x in range(len(datasection.data)):
	    c = datasection.data[x]
	    emu.set_memory(database + x, int(ord(c)), size=1)
	ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
	ep_ava = ep+pe.OPTIONAL_HEADER.ImageBase
	data = pe.get_memory_mapped_image()[ep:ep+40]
	
	emu.set_stack_argument(0x8, 0x10, name="arg_0")
	emu.set_stack_argument(0xc, 0x20, name="arg_4")
	if (ret):
		offset=0
		emu.set_register("EIP", entrypoint)
		emu.set_register("ECX", 0x00000000)
		emu.set_register("BL", 0x00)
		emu.set_register("DL", 0x00)
		instruction = "NOP"
		while  not instruction.startswith("loop") : #offset < len(data):
			i = pydasm.get_instruction(data[offset:], pydasm.MODE_32)	
  			instruction=pydasm.get_instruction_string(i, pydasm.FORMAT_INTEL, ep_ava+offset)
			offset+=i.length
  			print instruction
			#c = raw_input("emulator> ")
			
		while 1 : 
			value1 = emu.get_register("ECX")
			value2 = emu.get_register("BL")
			value3 = emu.get_register("DL")
			if(value1 != 0 and value2 !=0 and value3 != 0):
				break;
			emu.execute()
		byte_obs = value1	
		while value1 !=0:
			emu.execute()
			value1 =emu.get_register("ECX") 
		
		i = pydasm.get_instruction(data[offset:], pydasm.MODE_32)
		instruction=pydasm.get_instruction_string(i, pydasm.FORMAT_INTEL, ep_ava+offset)
		print instruction
		offset+=i.length
		emu.execute()
		
		#offset+=((ep_ava+offset)-  emu.get_register("EIP"))
		print "after jump"
		resu = emu.get_register("EIP")- (ep_ava+offset)
		print " %x  " % resu  
		print "%x" % emu.get_register("EIP")
		offset+=resu
		instruction = "nop"
		while  not instruction.startswith("jmp") : #offset < len(data):
			if ord(data[0]) == 0x90:
				print "nop"
			
			i = pydasm.get_instruction(data[offset:], pydasm.MODE_32)
			print "i " , i
			
  			instruction=pydasm.get_instruction_string(i, pydasm.FORMAT_INTEL, ep_ava+offset)
			emu.execute()
			offset+=i.length
  			print instruction
			#c = raw_input("emulator> ")
		ret=instruction.find("0x")
		jmp_address= instruction[ret+2:]
		#print "ret " , ret, hex(jmp_address)
		#emu.execute()
		#emu.execute()

		#print " I am here1 "
		emu.dump_regs()
		diff =abs(byte_obs-(emu.get_register("EIP")-codebase))
		print "diff " , diff
		exec_code =emu.get_memory(emu.get_register("EIP") ,diff )
		print hex(ord(exec_code[0]))
		idata = array.array('B', [0x68,0x2A,0x6A,0x01,0x6A,0x00,0xE8])
		signature = idata.tostring()	
		ret = SearchString(exec_code,signature,2)
		if ret :
			print "bad code "
		else:
			print "good code "
		
	








if __name__ == '__main__':
	if len(os.sys.argv)<2:
	        print 'Not enough arguments. Usage filename requd' 
	        os.sys.exit(1)
	findObsSignature(os.sys.argv[1])


	#print os.sys.argv
