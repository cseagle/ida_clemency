from idaapi import *

'''
Author: Chris Eagle
Name: Clemency database dump plugin defcon 25
What: Dumps the current .text section back to a packed 9-bit disk file
How: Install into <idadir>/plugins
     Activate  using Alt-9
'''

class clemency_dump_plugin_t(plugin_t):
   flags = 0
   wanted_name = "Dump Clemency Database to Clemency binary"
   wanted_hotkey = "Alt-9"
   comment = ""
   help = ""

   def init(self):
      return PLUGIN_OK

   def term(self):
      pass

   pats = [
      "0000", "0001", "0010", "0011", "0100", "0101", "0110", "0111",
      "1000", "1001", "1010", "1011", "1100", "1101", "1110", "1111"
   ]

   def run(self, arg):
      fname = AskFile(1, "*.*", "Choose save file")
      if fname is not None and len(fname) > 0:
         with open(fname, "wb") as f:
            text = get_segm_by_name(".text")
            bits = ''
            for i in range(text.startEA, text.endEA):
               b = Byte(i)
               if b & 0x100:
                  bits += '1'
               else:
                  bits += '0'
               bits += self.pats[(b >> 4) & 0xf]
               bits += self.pats[b & 0xf]

               while len(bits) >= 8:
                  f.write(chr(int(bits[0:8], 2)))
                  bits = bits[8:]

            if len(bits):
               while len(bits) % 8:
                  bits += '0'
               f.write(chr(int(bits[0:8], 2)))      

def PLUGIN_ENTRY():
   return clemency_dump_plugin_t()
