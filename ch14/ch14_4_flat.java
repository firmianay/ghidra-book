//Locate all calls to strcpy and sprintf
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
import java.util.List;
import java.util.ArrayList;

public class ch14_4_flat extends GhidraScript {

   public void list_calls(Function tgtfunc) {
      String fname = tgtfunc.getName();
      Address addr = tgtfunc.getEntryPoint();
      Reference refs[] = getReferencesTo(addr);
      for (int i = 0; i < refs.length; i++) {
         if (refs[i].getReferenceType().isCall()) {
            Address src = refs[i].getFromAddress();
            Function func = getFunctionContaining(src);
            if (func.isThunk()) {
               continue;
            }
            String caller = func.getName();
            long offset = src.getOffset();
            printf("%s is called from 0x%x in %s\n", fname, offset, caller);
         }
      }
   }

   public void getFunctions(String name, List<Function> list) {
      SymbolTable symtab = currentProgram.getSymbolTable();
      SymbolIterator si = symtab.getSymbolIterator();
      while (si.hasNext()) {
         Symbol s = si.next();
         if (s.getSymbolType() != SymbolType.FUNCTION || s.isExternal()) {
            continue;
         }
         if (s.getName().equals(name)) {
            list.add(getFunctionAt(s.getAddress()));
         }
      }
   }

   public void run() throws Exception {
      List<Function> funcs = new ArrayList<Function>();
      getFunctions("strcpy", funcs);
      getFunctions("sprintf", funcs);
      getFunctions("atoi", funcs);
      funcs.forEach((f) -> list_calls(f));
   }
}
