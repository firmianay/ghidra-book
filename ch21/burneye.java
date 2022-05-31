//burneye decoding example
//@author Chris Eagle
//@category Ghidrabook.CH21
//@keybinding 
//@menupath 
//@toolbar 

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;

public class burneye extends GhidraScript {

   public void run() throws Exception {
      int ECX = getInt(toAddr(0x5371000));   //from instruction 0537103D
      int ESI = 0x05371087;                  //from instruction 05371048
      int EDI = ESI;                         //from instruction 05371049
      int EBX = getInt(toAddr(0x5371004));   //from instruction 0537104B

      if (EBX != 0) {           //from instructions 05371051 and 05371053
         int EDX = 0;               //from instruction 05371059
         do {
            int EAX = 8;            //from instruction 0537105B
            do {
               //Ghidra does not offer an equivalent of the x86 shrd instruction so we
               //need to derive the behavior using several operations
               EDX = EDX >>> 1;             //perform unsigned shift right one bit
               int CF = EBX & 1;            //remember the low bit of EBX
               if (CF == 1) {               //CF represents the x86 carry flag
                  EDX = EDX | 0x80000000;   //shift in the low bit of EBX if it is 1
               }
               EBX = EBX >>> 1;             //perform unsigned shift right one bit
               if (CF == 1) {               //from instruction 05371066
                  EBX = EBX ^ 0xC0000057;   //from instruction 0537106C
               }
               EAX--;                    //from instruction 05371072
            } while (EAX != 0);          //from instruction 05371073
            EDX = EDX >>> 24;            //perform unsigned shift right 24 bits
            EAX = getByte(toAddr(ESI));  //from instruction 05371078
            ESI++;
            EAX = EAX ^ EDX;                 //from instruction 05371079
            clearListing(toAddr(EDI));       //make sure we can write back to Ghidra
            setByte(toAddr(EDI), (byte)EAX); //from instruction 0537107B
            EDI++;
            ECX--;                     //from instruction 0537107C
         } while (ECX != 0);           //from instruction 0537107D
      }
   }
}
