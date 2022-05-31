//Count the number of instructions in a function
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
import ghidra.program.model.pcode.*;
import ghidra.program.model.address.*;

public class ch14_2_flat extends GhidraScript {

    public void run() throws Exception {
       Listing plist = currentProgram.getListing();
       Function func = getFunctionContaining(currentAddress);
       if (func != null) {
          InstructionIterator iter = plist.getInstructions(func.getBody(), true);
          int count = 0;
          while (iter.hasNext() && !monitor.isCancelled()) {
             count++; 
             Instruction ins = iter.next();
          }  
          popup(String.format("%s contains %d instructions\n", func.getName(), count));
       }
       else {
          popup(String.format("No function found at location %x", currentAddress.getOffset()));
       }
   }
}
