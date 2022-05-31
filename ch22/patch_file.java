//Dump the current Ghidra program bytes to a new
//file.  Include patchd bytes, ignore relocations
//@author CE
//@category Ghidrabook.CH22
//@keybinding 
//@menupath 
//@toolbar 

import ghidra.app.script.GhidraScript;
import ghidra.program.model.reloc.*;
import ghidra.program.model.mem.*;
import ghidra.program.database.mem.*;
import java.util.*;
import java.io.*;

public class patch_file extends GhidraScript {

   public void saveBytes(FileBytes fb, OutputStream os, Set<Long> exclusions) throws Exception {
      long begin = fb.getFileOffset();
      long end = begin + fb.getSize();
      for (long offset = begin; offset < end; offset++) {
         int orig = fb.getOriginalByte(offset) & 0xff;
         int mod = fb.getModifiedByte(offset) & 0xff;
         if (!exclusions.contains(offset) && orig != mod) {
            os.write(mod);
         }
         else {
            os.write(orig);
         }
      } 
   }

   public void writePatchFile(FileBytes fb, OutputStream os) throws Exception {
      Memory mem = currentProgram.getMemory();
      Iterator<Relocation> relocs = currentProgram.getRelocationTable().getRelocations();
      HashSet<Long> exclusions = new HashSet<Long>();
      while (relocs.hasNext()) {
         Relocation r = relocs.next();
         AddressSourceInfo info = mem.getAddressSourceInfo(r.getAddress());
         for (long off = 0; off < r.getBytes().length; off++) { 
            exclusions.add(info.getFileOffset() + off);
         }
      }
      saveBytes(fb, os, exclusions);
   }

   public void run() throws Exception {
      Memory mem = currentProgram.getMemory();
      java.util.List<FileBytes> fbytes = mem.getAllFileBytes();
      if (fbytes.size() != 1) {
         //Can't handle more than one set of FileBytes
         return;
      }
      FileBytes fb = fbytes.get(0);
      File of = askFile("Choose file to patch", "Save");
      FileOutputStream fos = new FileOutputStream(of, false);
      writePatchFile(fb, fos);
      fos.close();
   }

}
