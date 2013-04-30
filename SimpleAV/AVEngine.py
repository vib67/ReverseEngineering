
import os, sys
import array
sys.path.append("..")
sys.path.append("../lib")
import pydasm
import pefile
from PyEmu import PEPyEmu
import string
class AVEngine:
	def __init__(self):
		self.imagebase = 0
		self.codebase = 0
		self.database = 0
		self.bytesobs =0	
		self.deobsbytes=0
		self.entrypoint =0
		self.pe = 0
		self.emu=0
		self.obsfucated=0
		

	
	def SearchString(self,text, pattern, no_of_split):
		patterns=pattern.split("*", no_of_split)
	
		for  pattern in patterns:
		
			offset = text.find(pattern)
			if(offset == -1):
				print "not found"  ,hex(ord(pattern[0])), offset
				return 0 
			text= text[offset+len(pattern):]

		return 1


	def init(self ,filename):
		
		if filename:
    			self.pe = pefile.PE(filename)
		else:
   			print "[!] Blank filename specified"
    			sys.exit(2)
	
		self.imagebase = self.pe.OPTIONAL_HEADER.ImageBase
		self.codebase = self.pe.OPTIONAL_HEADER.ImageBase + self.pe.OPTIONAL_HEADER.BaseOfCode
		self.database = self.pe.OPTIONAL_HEADER.ImageBase + self.pe.OPTIONAL_HEADER.BaseOfData
		self.entrypoint = self.pe.OPTIONAL_HEADER.ImageBase + self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
		print "[*] Image Base Addr:  0x%08x" % (self.imagebase)
		print "[*] Code Base Addr:   0x%08x" % (self.codebase)
		print "[*] Data Base Addr:   0x%08x" % (self.database)
		print "[*] Entry Point Addr: 0x%08x\n" % (self.entrypoint)
		self.emu = PEPyEmu()


	def isfileobsfucated(self):
		ep = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
		ep_ava = ep+self.pe.OPTIONAL_HEADER.ImageBase
		data = self.pe.get_memory_mapped_image()[ep:ep+40]
		
		#idata = array.array('B', [0xb9,0x5a,0x01,0x00,0x00,0x43,0x4b,0xbe,0x00,0x10,0x40,0x00,0xb3,0xa6,0x8a,0x16,0x32,0xd3])
		idata = array.array('B', [0xB9,0x2A,0xBE,0x2A,0xB3,0x2A,0x8A,0x16,0x32,0xD3,0x8A,0x1E,0x88,0x16,0x46,0xE2,0x2A,0xE9])
		signature = idata.tostring()
		#ret= data.find(data,signature,4)
		ret=  self.SearchString(data,signature,5)
		#print "Signature " ,ret
		self.obsfucated = ret
		return ret

	def initalizesections(self):
		for section in self.pe.sections:
			if section.Name.startswith(".text"):
        			textsection = section
    			elif section.Name.startswith(".rdata"):
        			datasection = section
		self.codelen = len(textsection.data)
		for x in range(len(textsection.data)):
	    		c = textsection.data[x]
	   	 	self.emu.set_memory(self.codebase + x, int(ord(c)), size=1)
		self.datalen = len(datasection.data)
		for x in range(len(datasection.data)):
	   		 c = datasection.data[x]
	   		 self.emu.set_memory(self.database + x, int(ord(c)), size=1)
		self.emu.set_stack_argument(0x8, 0x10, name="arg_0")
		self.emu.set_stack_argument(0xc, 0x20, name="arg_4")

	def checkmalware(self) :
		if(self.obsfucated) :
			self.deobsbytes =abs(self.bytesobs-(self.emu.get_register("EIP")-self.codebase))
			#print "diff " , diff
			exec_code =self.emu.get_memory(self.emu.get_register("EIP") ,self.deobsbytes )
			#print hex(ord(exec_code[0]))
			
			
		else :
			self.initalizesections()
			exec_code = self.emu.get_memory(self.codebase ,self.codelen )
		idata = array.array('B', [0x68,0x2A,0x6A,0x01,0x6A,0x00,0xE8])
		signature = idata.tostring()	
		ret = self.SearchString(exec_code,signature,2)	
		if ret :
			print "bad code "
		else:
			print "good code "

	def deobsfucate(self) :	
	
		
		self.initalizesections()

		ep = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
		ep_ava = ep+self.pe.OPTIONAL_HEADER.ImageBase
		data = self.pe.get_memory_mapped_image()[ep:ep+40]
	
		

		offset=0
		self.emu.set_register("EIP", self.entrypoint)
		self.emu.set_register("ECX", 0x00000000)
		self.emu.set_register("BL", 0x00)
		self.emu.set_register("DL", 0x00)
		instruction = "NOP"
		while  not instruction.startswith("loop") : #offset < len(data):
			i = pydasm.get_instruction(data[offset:], pydasm.MODE_32)	
  			instruction=pydasm.get_instruction_string(i, pydasm.FORMAT_INTEL, ep_ava+offset)
			offset+=i.length
  			print instruction
			#c = raw_input("emulator> ")
			
		while 1 : 
			value1 = self.emu.get_register("ECX")
			value2 = self.emu.get_register("BL")
			value3 = self.emu.get_register("DL")
			if(value1 != 0 and value2 !=0 and value3 != 0):
				break;
			self.emu.execute()
		self.bytesobs = value1	
		byte_obs = value1	
		while value1 !=0:
			self.emu.execute()
			value1 =self.emu.get_register("ECX") 
		
		i = pydasm.get_instruction(data[offset:], pydasm.MODE_32)
		instruction=pydasm.get_instruction_string(i, pydasm.FORMAT_INTEL, ep_ava+offset)
		print instruction
		offset+=i.length
		self.emu.execute()
		
		#offset+=((ep_ava+offset)-  emu.get_register("EIP"))
		
		nxt_offset = self.emu.get_register("EIP")- (ep_ava+offset)
		
		
		offset+=nxt_offset
		instruction = "nop"
		while  not instruction.startswith("jmp") : #   offset < len(data)
			i = pydasm.get_instruction(data[offset:], pydasm.MODE_32)
			instruction=pydasm.get_instruction_string(i, pydasm.FORMAT_INTEL, ep_ava+offset)
			self.emu.execute()
			offset+=i.length
  			print instruction
			#c = raw_input("emulator> ")
		ret=instruction.find("0x")
		jmp_address= instruction[ret+2:]
		
		#emu.execute()
		#emu.execute()
		#self.emu.dump_regs()
		#self.deobsbytes =abs(byte_obs-(self.emu.get_register("EIP")-self.codebase))
		#print "diff " , diff
		#exec_code =self.emu.get_memory(self.emu.get_register("EIP") ,self.deobsbytes )
		#print hex(ord(exec_code[0]))
		#idata = array.array('B', [0x68,0x2A,0x6A,0x01,0x6A,0x00,0xE8])
		#signature = idata.tostring()	
		#ret = self.SearchString(exec_code,signature,2)
		#if ret :
		#	print "bad code "
		#else:
		#	print "good code "
		
	








#if __name__ == '__main__':
#	if len(os.sys.argv)<2:
#	        print 'Not enough arguments. Usage filename requd' 
#	        os.sys.exit(1)
#	av= AVEngine()	
#	av.init(os.sys.argv[1])
#	if av.isfileobsfucated():
#		print " yes it is obsfucated "
#		av.deobsfucate()
#		
#	else:
#		print " No it is not obsfucated "
#	av.checkmalware()

	#print os.sys.argv
