//TODO write a description for this script
//@author 
//@category Ghidrabook.CH14
//@keybinding 
//@menupath 
//@toolbar 

import ghidra.app.script.GhidraScript;
import ghidra.program.model.util.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.address.*;

public class ch14_5_flat extends GhidraScript {

public void run() throws Exception {
   int local_8 = 0;
   while (local_8 <= 0x3C1) {
      long edx = local_8;
      edx = edx + 0x804B880;
      long eax = local_8;
      eax = eax + 0x804B880;
      int al = getByte(toAddr(eax));
      al = al ^ 0x4B;
      setByte(toAddr(edx), (byte)al);
      local_8++;
   }
}

}
