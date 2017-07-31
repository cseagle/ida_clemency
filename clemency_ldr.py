import idaapi
from idaapi import *
import idc
from idc import *

'''
Author: Chris Eagle
Name: Clemency loader for defcon 25
How: Install into <idadir>/loaders
     Choose this when loading a clemency 9-bit middle-endian binary
'''

#Verify the input file format
#   li - loader_input_t object. See IDA help file for more information
#   n  - How many times we have been called
#Returns: 
#   0 - file unrecognized
#   Name of file type - if file is recognized
def accept_file(li, n):
   if (n):
      #this plugin only examines file on first time calle
      #returns 0 for all subsequent calls
      return 0
   return "Clemency Loader"

#Load the file
#   li - loader_input_t object
#   neflags - refer to loader.hpp for valid flags
#   format  - The file format selected by the user
#Returns:
#   1 - success
#   0 - failure
def load_file(li, neflags, format):
   #set_processor_type("clemency", SETPROC_COMPAT)
   
   #This example starts reading from the start of the file
   li.seek(0)

   sz = li.size()
   
   add_segm(0, 0, (sz * 8) // 9, ".text", "CODE")
   
   # create a segment
   #use the idaapi function add_segm to create segments around bytes you have read
   #into your database
   #prototype is: add_segm(paragraph, startAddress, endAddress, segmentName, segmentClass)
   #   actual base address is computed as:  (paragraph << 4) + startAddress
   #   paragraph is usually 0 for non-segmented architecutres
   #modify this to match the format of your input file type
   add_segm(0, 0x4000000, 0x4000021, ".clock", "DATA")
   add_segm(0, 0x4010000, 0x4011000, ".flagio", "DATA")
   add_segm(0, 0x5000000, 0x5002003, ".datarx", "DATA")
   add_segm(0, 0x5010000, 0x5012003, ".datatx", "DATA")
   add_segm(0, 0x6000000, 0x6800000, ".shared", "DATA")
   add_segm(0, 0x6800000, 0x7000000, ".nvram", "DATA")
   add_segm(0, 0x7FFFF00, 0x7FFFF1C, ".irqptrs", "DATA")
   add_segm(0, 0x7FFFF80, 0x8000000, ".procid", "DATA")

   doByte(0x4010000, 0x1000)
   add_entry(0x4010000, 0x4010000, "FlagIO", 0)

   doByte(0x5000000, 0x2000)
   add_entry(0x5000000, 0x5000000, "DataReceived", 0)
   do3byte(0x5002000, 1)
   add_entry(0x5002000, 0x5002000, "DataReceivedSize", 0)
   
   doByte(0x5010000, 0x2000)
   add_entry(0x5010000, 0x5010000, "DataSent", 0)
   do3byte(0x5012000, 1)
   add_entry(0x5012000, 0x5012000, "DataSentSize", 0)

   doByte(0x6000000, 0x800000)
   add_entry(0x6000000, 0x6000000, "Shared", 0)

   doByte(0x6800000, 0x800000)
   add_entry(0x6800000, 0x6800000, "NVRAM", 0)

   # add the initial entry point
   #add_entry is an idaapi function used to add entry points which form the initial list
   #of code locations to be explored by the processor module once loading is completed
   #prototype is add_entry(ordinal, address, name, makeCode)
   #   ordinal is the ordinal number of the entry point. If the entry has no ordinal, set ordinal == address
   #   address is the address of the entry point
   #   name is the name of the entry point
   #   makeCode should be set to 1 if the entry point is code, 0 otherwise (ie for exported data)
   #modify this to match the format of your input file type
   add_entry(0, 0, "_start", 1)

   add_entry(0x4000000, 0x4000000, "timer1_delay", 0)
   do3byte(0x4000000, 3)
   add_entry(0x4000003, 0x4000003, "timer1_remain", 0)
   do3byte(0x4000003, 3)
   add_entry(0x4000006, 0x4000006, "timer2_delay", 0)
   do3byte(0x4000006, 3)
   add_entry(0x4000009, 0x4000009, "timer2_remain", 0)
   do3byte(0x4000009, 3)
   add_entry(0x400000c, 0x400000c, "timer3_delay", 0)
   do3byte(0x400000c, 3)
   add_entry(0x400000f, 0x400000f, "timer3_remain", 0)
   do3byte(0x400000f, 3)
   add_entry(0x4000012, 0x4000012, "timer4_delay", 0)
   do3byte(0x4000012, 3)
   add_entry(0x4000015, 0x4000015, "timer4_remain", 0)
   do3byte(0x4000015, 3)
   add_entry(0x4000018, 0x4000018, "epoch", 0)
   MakeComm(0x4000018, "Number of seconds since Aug. 02, 2013 09:00 PST")
   add_entry(0x400001e, 0x400001e, "ticks", 0)
   MakeComm(0x400001e, "Number of processing ticks since processor start")
   do3byte(0x400001e, 3)

   add_entry(0x7FFFF00, 0x7FFFF00, "timer1_handler", 0)
   do3byte(0x7FFFF00, 3)
   add_entry(0x7FFFF03, 0x7FFFF03, "timer2_handler", 0)
   do3byte(0x7FFFF03, 3)
   add_entry(0x7FFFF06, 0x7FFFF06, "timer3_handler", 0)
   do3byte(0x7FFFF06, 3)
   add_entry(0x7FFFF09, 0x7FFFF09, "timer4_handler", 0)
   do3byte(0x7FFFF09, 3)
   add_entry(0x7FFFF0c, 0x7FFFF0c, "invalid_inst_handler", 0)
   do3byte(0x7FFFF0c, 3)
   add_entry(0x7FFFF0f, 0x7FFFF0f, "divide_by_zero_handler", 0)
   do3byte(0x7FFFF0f, 3)
   add_entry(0x7FFFF12, 0x7FFFF12, "memory_exc_handler", 0)
   do3byte(0x7FFFF12, 3)
   add_entry(0x7FFFF15, 0x7FFFF15, "datarx_handler", 0)
   do3byte(0x7FFFF15, 3)
   add_entry(0x7FFFF18, 0x7FFFF18, "datatx_handler", 0)
   do3byte(0x7FFFF18, 3)

   add_entry(0x7FFFF80, 0x7FFFF80, "processor_name", 0)
   doByte(0x7FFFF80, 32)
   add_entry(0x7FFFFA0, 0x7FFFFA0, "processor_version", 0)
   do3byte(0x7FFFFA0, 3)
   add_entry(0x7FFFFA3, 0x7FFFFA3, "processor_functionality", 0)
   do3byte(0x7FFFFA3, 3)
#   add_entry(0x7FFFFA6, 0x7FFFFA6, "FutureUse", 0)
   add_entry(0x7FFFFF0, 0x7FFFFF0, "interrupt_stack_direction", 0)
   doByte(0x7FFFFF0, 1)
#   add_entry(0x7FFFFF1, 0x7FFFFF1, "FutureUse", 0)


   pats = [
      "0000", "0001", "0010", "0011", "0100", "0101", "0110", "0111",
      "1000", "1001", "1010", "1011", "1100", "1101", "1110", "1111"
   ]

   blob = li.read(sz) #bytes(sz, 0)
   
   binary = ''
   
   ea = 0
   for b in blob:
      binary += pats[ord(b) >> 4] + pats[ord(b) & 0xf]
      if len(binary) >= 9:
         nb = int(binary[0:9], 2)
         patch_byte(ea, nb)
         ea += 1
         binary = binary[9:]

   SetLongPrm(INF_STRTYPE, ASCSTR_UNICODE)
   set_compiler_id(COMP_GNU)
   
   return 1;
