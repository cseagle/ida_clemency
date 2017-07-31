from idaapi import *

'''
Author: Chris Eagle
Name: Clemency function fixup plugin defcon 25
How: Install into <idadir>/plugins
     Activate within a function using Alt-8
'''

class clemency_plugin_t(plugin_t):
   flags = 0
   wanted_name = "Fix Clemency Functions"
   wanted_hotkey = "Alt-8"
   comment = ""
   help = ""

   def init(self):
      return PLUGIN_OK

   def term(self):
      pass

   def run(self, arg):
      f = get_func(ScreenEA())
      if f is not None:
         fitems = FuncItems(f.startEA)
         for a in fitems:
            for x in XrefsFrom(a, XREF_FAR):
               if x.type == fl_JN:
                  if not isCode(GetFlags(x.to)):
                     do_unknown(ItemHead(x.to), 0)
                     MakeCode(x.to)
               elif x.type == fl_CN:
                  if not isCode(GetFlags(x.to)):
                     do_unknown(ItemHead(x.to), 0)
                     MakeCode(x.to)
                  MakeFunction(x.to, BADADDR)                     

def PLUGIN_ENTRY():
   return clemency_plugin_t()
