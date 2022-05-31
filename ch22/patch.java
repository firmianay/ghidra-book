//Demonstrate scripted byte patching
//@author CE
//@category Ghidrabook.CH22
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

public class patch extends GhidraScript {

   public void patchBytes(Address start, byte[] patch) throws Exception {
       Address end = start.add(patch.length);
       clearListing(start, end);
       setBytes(start, patch);
    }

    public void run() throws Exception { 
       byte[] patch = {(byte)0x90, (byte)0x90, (byte)0x90, (byte)0x90, (byte)0x90, (byte)0x90, (byte)0x90, (byte)0x90, (byte)0x90, (byte)0x90,};
       patchBytes(currentAddress, patch);
    }

}
