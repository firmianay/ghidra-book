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
 */
// Counts the number of defined strings that match a regex in the current
// selection, or current program if no selection is made, and displays the
// results on the console
//
//@author Ghidrabook, KN 
//@category Ghidrabook.CH14
//@keybinding 
//@menupath 
//@toolbar 

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramSelection;

import java.io.*;

public class FindStringsByRegex extends GhidraScript {

	@Override
	public void run() throws Exception {
		String regex =
			askString("Please enter the regex",
				      "Please enter the regex you're looking to match:");
		
		Listing listing = currentProgram.getListing();
		
		DataIterator dataIt;
		if (currentSelection != null) {
			dataIt = listing.getDefinedData(currentSelection, true);
		} else {
			dataIt = listing.getDefinedData(true);
		}

		Data data;
		String type;
		int counter = 0;
		while (dataIt.hasNext() && !monitor.isCancelled()) {
			data = dataIt.next();
			type = data.getDataType().getName().toLowerCase();
			if (type.contains("unicode") || type.contains("string")) {
				String s = data.getDefaultValueRepresentation();
				if (s.matches(regex)) {
					counter++;
					println(s);
				}
			}
		}
		println(counter + " matching strings were found");
	}
}