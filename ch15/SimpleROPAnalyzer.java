/* ###
 * IP: GHIDRA
 *
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
 *
 * Author: KN
 */
package simplerop;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Identifies potential ROP gadgets in a binary.  Writes each gadget to a file
 * named <program_name>_gadgets.txt
 *
 * Uses a very simple approach, and will certainly a) not identify all gadgets
 * in a binary, and b) identify gadgets that may not be useful.
 */
public class SimpleROPAnalyzer extends AbstractAnalyzer {

   private int gadgetCount = 0;      // Counts the number of gadgets
   private BufferedWriter outFile;   // Output file

   // List of "interesting" instructions
   private List<String> usefulInstructions = Arrays.asList(
      "NOP", "POP", "PUSH", "MOV", "ADD", "SUB", "MUL", "DIV", "XOR");

   // List of "interesting" instructions that don’t have operands
   private List<String> require0Operands = Arrays.asList("NOP");

   // List of "interesting" instructions that have one operand
   private List<String> require1RegOperand = Arrays.asList("POP", "PUSH");

   // List of "interesting" instructions for which we want the first parameter to be a register
   private List<String> requireFirstRegOperand = Arrays.asList(
      "MOV", "ADD", "SUB", "MUL", "DIV", "XOR");

   // List of "start" instructions that have ZERO operands
   private List<String> startInstr0Params = Arrays.asList("RET");

   // List of "start" instructions that have one operand
   private List<String> startInstr1RegParam = Arrays.asList("JMP", "CALL");

   public SimpleROPAnalyzer() {
      super("SimpleROP",
           "Parses a file and searches for ROP gadgets",
           AnalyzerType.INSTRUCTION_ANALYZER);
   }

   @Override
   public boolean getDefaultEnablement(Program program) {
      return false;
   }

   @Override
   public boolean canAnalyze(Program program) {
      return true;
   }

   @Override
   public void registerOptions(Options options, Program program) {
   }

   @Override
   public boolean added(Program program, AddressSetView set,
                        TaskMonitor monitor, MessageLog log)
                        throws CancelledException {
      gadgetCount = 0;

      String outFileName = System.getProperty("user.home") + "/" +
                           program.getName() + "_gadgets.txt";
      monitor.setMessage("Searching for ROP Gadgets");
      try {
         outFile = new BufferedWriter(new FileWriter(outFileName));
      } catch (IOException e) {/* pass */}

      // iterate through each instruction in the binary
      Listing code = program.getListing();
      InstructionIterator instructions = code.getInstructions(set, true);

      while (instructions.hasNext() && !monitor.isCancelled()) {
         Instruction inst = instructions.next();
         if (isStartInstruction(inst)) {
            // We found an "start" instruction.  This will be the last
            // instruction in the potential ROP gadget so we will try to
            // build the gadget from here
            ArrayList<Instruction> gadgetInstructions =
               new ArrayList<Instruction>();
            gadgetInstructions.add(inst);
            Instruction prevInstr = inst.getPrevious();
            buildGadget(program, monitor, prevInstr, gadgetInstructions);
         }
      }
      try {
         outFile.close();
      } catch (IOException e) {/* pass */}

      return true;
   }

   private void buildGadget(Program program, TaskMonitor monitor, Instruction inst,
                     ArrayList<Instruction> gadgetInstructions) {
      if (inst == null || !isUsefulInstruction(inst) ||
         monitor.isCancelled()) {
         return;
      }
      gadgetInstructions.add(inst);
      buildGadget(program, monitor, inst.getPrevious(), gadgetInstructions);
      gadgetCount += 1;
      for (int ii = gadgetInstructions.size() - 1; ii >= 0; ii--) {
         try {
            Instruction insn = gadgetInstructions.get(ii);
            if (ii == gadgetInstructions.size() - 1) {
               outFile.write(insn.getMinAddress() + ";");
            }
            outFile.write(insn.toString() + ";");
         } catch (IOException e) {/* pass */}
      }
      try {
         outFile.write("\n");
      } catch (IOException e) {/* pass */}

      // Report count to monitor every 100th gadget
      if (gadgetCount % 100 == 0) {
         monitor.setMessage("Found " + gadgetCount + " ROP Gadgets");
      }

      gadgetInstructions.remove(gadgetInstructions.size() - 1);
   }

   private boolean isUsefulInstruction(Instruction inst) {
      if (!usefulInstructions.contains(inst.getMnemonicString())) {
         return false;
      }
      if (require0Operands.contains(inst.getMnemonicString())) {
         return true;
      }
      if (require1RegOperand.contains(inst.getMnemonicString()) &&
         inst.getNumOperands() == 1) {
         Object[] opObjects0 = inst.getOpObjects(0);
         for (int ii = 0; ii < opObjects0.length; ii++) {
            if (opObjects0[ii] instanceof Register) {
               return true;
            }
         }
      }
      if (requireFirstRegOperand.contains(inst.getMnemonicString()) &&
         inst.getNumOperands() >= 1) {
         Object[] opObjects0 = inst.getOpObjects(0);
         for (int ii = 0; ii < opObjects0.length; ii++) {
            if (opObjects0[ii] instanceof Register) {
               return true;
            }
         }
      }
      return false;
   }

   private boolean isStartInstruction(Instruction inst) {
      if (startInstr0Params.contains(inst.getMnemonicString())) {
         return true;
      }
      if (startInstr1RegParam.contains(inst.getMnemonicString()) &&
         inst.getNumOperands() >= 1) {
         Object[] opObjects0 = inst.getOpObjects(0);
         for (int ii = 0; ii < opObjects0.length; ii++) {
            if (opObjects0[ii] instanceof Register) {
               return true;
            }
         }
      }
      return false;
   }
}
