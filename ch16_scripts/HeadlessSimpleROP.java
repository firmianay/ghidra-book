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
*/
// Identifies potential ROP gadgets in a binary.  Writes each gadget to a file
// named <program_name>_gadgets.txt, and appends the number of gadgets found in
// the file to gadget_summary.txt in the user's home directory
//@author Ghidrabook, KN
//@category Ghidrabook.CH16
//@keybinding
//@menupath
//@toolbar

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;

public class HeadlessSimpleROP extends GhidraScript {
	
	private int gadgetCount = 0;      // Counts the number of gadgets
	private BufferedWriter outFile;   // Output file

	// List of “interesting” instructions
	private List<String> usefulInstructions = Arrays.asList(
		"NOP", "POP", "PUSH", "MOV", "ADD", "SUB", "MUL", "DIV", "XOR");

	// List of “interesting” instructions that don’t have operands
	private List<String> require0Operands = Arrays.asList("NOP");

	// List of “interesting” instructions that have one operand
	private List<String> require1RegOperand = Arrays.asList("POP", "PUSH");

	// List of “interesting” instructions for which we want the first parameter to be a register
	private List<String> requireFirstRegOperand = Arrays.asList(
		"MOV", "ADD", "SUB", "MUL", "DIV", "XOR");

	// List of “start” instructions that have ZERO operands
	private List<String> startInstr0Params = Arrays.asList("RET");

	// List of “start” instructions that have one operand
	private List<String> startInstr1RegParam = Arrays.asList("JMP", "CALL");

	@Override
	protected void run() throws Exception {
		gadgetCount = 0;
		
		String outFileName = System.getProperty("user.home") + "/" +
			currentProgram.getName() + "_gadgets.txt";
		outFile = new BufferedWriter(new FileWriter(outFileName));
		
		// iterate through each instruction in the binary
		Instruction instruction = getFirstInstruction();
		
		while (instruction.getNext() != null && !monitor.isCancelled()) {
			instruction = instruction.getNext();
			if (isStartInstruction(instruction)) {
				// We found an "start" instruction.  This will be the last
				// instruction in the potential ROP gadget so we will try to
				// find the gadget from here
				ArrayList<Instruction> gadgetInstructions =
					new ArrayList<Instruction>();
				gadgetInstructions.add(instruction);
				Instruction prevInstr = instruction.getPrevious();
				this.findGadget(prevInstr, gadgetInstructions);
			}
		}
		outFile.close();
			
		// now update the summary file (i.e., append to it)
		String summaryFileName = System.getProperty("user.home") + "/gadget_summary.txt";
		outFile = new BufferedWriter(new FileWriter(summaryFileName, true));
		outFile.write(currentProgram.getName() + ": Found " + gadgetCount + " potential gadgets\n");
		outFile.close();
	}
	
	private void findGadget(Instruction instr, ArrayList<Instruction> gadgetInstructions) throws Exception {
		if (instr == null || !isUsefulInstruction(instr) ||
				monitor.isCancelled()) {
			return;
		}
		gadgetInstructions.add(instr);
		findGadget(instr.getPrevious(), gadgetInstructions);
		gadgetCount += 1;
		for (int ii = gadgetInstructions.size() - 1; ii >= 0; ii--) {
			if (ii == gadgetInstructions.size() - 1) {
				outFile.write(gadgetInstructions.get(ii).getMinAddress() + ";");
			}
			outFile.write(gadgetInstructions.get(ii).toString() + ";");
		}
		outFile.write("\n");
		
		gadgetInstructions.remove(gadgetInstructions.size() - 1);
	}

	private boolean isUsefulInstruction(Instruction instr) {
		if (!usefulInstructions.contains(instr.getMnemonicString())) {
			return false;
		}
		if (require0Operands.contains(instr.getMnemonicString())) {
			return true;
		}
		if (require1RegOperand.contains(instr.getMnemonicString()) &&
				instr.getNumOperands() == 1) {
			Object[] opObjects0 = instr.getOpObjects(0);
			for (int ii = 0; ii < opObjects0.length; ii++) {
				if (opObjects0[ii] instanceof Register) {
					return true;
				}
			}
		}
		if (requireFirstRegOperand.contains(instr.getMnemonicString()) &&
				instr.getNumOperands() >= 1) {
			Object[] opObjects0 = instr.getOpObjects(0);
			for (int ii = 0; ii < opObjects0.length; ii++) {
				if (opObjects0[ii] instanceof Register) {
					return true;
				}
			}
		}
		return false;
	}

	private boolean isStartInstruction(Instruction instr) {
		if (startInstr0Params.contains(instr.getMnemonicString())) {
			return true;
		}
		if (startInstr1RegParam.contains(instr.getMnemonicString()) &&
				instr.getNumOperands() >= 1) {
			Object[] opObjects0 = instr.getOpObjects(0);
			for (int ii = 0; ii < opObjects0.length; ii++) {
				if (opObjects0[ii] instanceof Register) {
					return true;
				}
			}
		}
		return false;
	}
}
