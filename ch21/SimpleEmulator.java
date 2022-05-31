/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/
// A simplified emulator for Ghidra, which emulates instructions and then
// displays the state of the program (to include registers, the stack, and
// local variables in the function the emulation ends in).
//@author KN 
//@category Emulator
//@keybinding 
//@menupath 
//@toolbar 

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.List;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.ByteProvider;
import ghidra.pcode.emulate.EmulateExecutionState;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.lang.*;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataType;

public class VerySimpleEmulator extends GhidraScript {

    private EmulatorHelper emuHelper;
    private Address executionAddress;
    private Address endAddress;


    public void run() throws Exception {
        // Create the emulation helper object
        emuHelper = new EmulatorHelper(currentProgram);
        emuHelper.enableMemoryWriteTracking(true);
        
        // Identify address range to be emulated.  If a portion of the program
        // is selected then use that selection, otherwise ask the user for
        // start and end addresses
        if (currentSelection != null) {
            executionAddress = currentSelection.getMinAddress();
            endAddress = currentSelection.getMaxAddress().next();
        } else {
            println("Nothing selected");
            return;
        }

        // Obtain entry instruction in order to establish initial processor context
        Instruction executionInstr = getInstructionAt(executionAddress);
        if (executionInstr == null) {
            printerr("Instruction not found at start address: " + executionAddress);
            return;
        }

        try {
            // Initialize stack pointer just below half of the program's address space
            // This is approximately where you might expect Windows stack to start
            long stackOffset = (executionInstr.getAddress().getAddressSpace().getMaxAddress().getOffset() >>> 1) - 0x7fff;
            emuHelper.writeRegister(emuHelper.getStackPointerRegister(), stackOffset);

            // Setup breakpoint at the end address
            emuHelper.setBreakpoint(endAddress);
            boolean continuing = false;

            // Emulate until  emulation script is cancelled or we reach the ending address
            while (!monitor.isCancelled() && !emuHelper.getExecutionAddress().equals(endAddress)) {
                if (continuing) {
                	emuHelper.run(monitor);
                } else {
                	emuHelper.run(executionAddress, executionInstr, monitor);
                }
                // get the address at which we hit the breakpoint or error
                executionAddress = emuHelper.getExecutionAddress();
                
                if (emuHelper.getEmulateExecutionState() == EmulateExecutionState.BREAKPOINT) {
                	continuing = true;
                } else if (monitor.isCancelled()) {
                	println("Emulation cancelled at 0x" + executionAddress);
                	continuing = false;
                } else {
                	println("Emulation error at 0x" + executionAddress + ": " + emuHelper.getLastError());
                	continuing = false;
               }
                writeBackMemory();
                if (!continuing) {
                	break;
                }
            }

        } finally {
            // cleanup resources and release hold on currentProgram
            emuHelper.dispose();
        }
    }
    
    private void writeBackMemory() {
        AddressSetView memWrites = emuHelper.getTrackedMemoryWriteSet();
        AddressIterator aIter = memWrites.getAddresses(true);
        Memory mem = currentProgram.getMemory();
        while(aIter.hasNext()) {
            Address a = aIter.next();
            MemoryBlock mb = getMemoryBlock(a);
            if (mb == null) {
                continue;
            }
            if (!mb.isInitialized()) {
                // initialize memory
                    try {
                        mem.convertToInitialized(mb, (byte)0x00);
                    } catch (Exception e) {
                        println(e.toString());
                    }
                }
                try {
                    mem.setByte(a, emuHelper.readMemoryByte(a));
                } catch (Exception e) {
                    println(e.toString());
                }
            } 
        }
 

}
