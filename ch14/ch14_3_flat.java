//Print function calls made from the cursor function
//@author Ghidrabook
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
import ghidra.program.model.address.*;
import java.util.List;

public class ch14_3_flat extends GhidraScript {

   public void run() throws Exception {
      Listing plist = currentProgram.getListing();
      Function func = getFunctionContaining(currentAddress);
      if (func != null) {
         String fname = func.getName();
         InstructionIterator iter = plist.getInstructions(func.getBody(), true);
         while (iter.hasNext() && !monitor.isCancelled()) {
            Instruction ins = iter.next();
            Address addr = ins.getMinAddress();
            Reference refs[] = ins.getReferencesFrom();
            for (int i = 0; i < refs.length; i++) {
               if (refs[i].getReferenceType().isCall()) {
                  Address tgt = refs[i].getToAddress();
                  Symbol sym = getSymbolAt(tgt);
                  String sname = sym.getName();
                  long offset = addr.getOffset();
                  printf("%s calls %s at 0x%x\n", fname, sname, offset);
               }
            }
         }  
      }
   }

}
