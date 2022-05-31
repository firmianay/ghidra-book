//Enumerate all functions in a program using the Flat API
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

public class ch14_1_flat extends GhidraScript {

   public void run() throws Exception {
      int ptrSize = currentProgram.getDefaultPointerSize();
      Function func = getFirstFunction();
      while (func != null && !monitor.isCancelled()) {
         String name = func.getName();
         long addr = func.getBody().getMinAddress().getOffset();
         long end = func.getBody().getMaxAddress().getOffset();
         StackFrame frame = func.getStackFrame();
         int locals = frame.getLocalSize();
         int args = frame.getParameterSize();
         printf("Function: %s, starts at %x, ends at %x\n", name, addr, end);
         printf("  Local variable area is %d bytes\n", locals);
         printf("  Arguments use %d bytes (%d args)\n", args, args / ptrSize);
         func = getFunctionAfter(func);
      }
   }
}
