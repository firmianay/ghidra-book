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
package simpleshellcode;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.LoaderTier;
import ghidra.framework.model.DomainObject;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.CompilerSpecDescription;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.lang.LanguageDescription;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Loads shellcode from source code into Ghidra, including setting an entry point.
 */
public class SimpleShellcodeSourceLoader extends AbstractLibrarySupportLoader {
	// pattern to find shellcode bytes in source (so we match on strings like "\xFF")
	private String pattern = "\\\\x[0-9a-fA-F]{1,2}";	
	
	@Override
	public LoaderTier getTier() {
		return LoaderTier.UNTARGETED_LOADER;
	}

	@Override
	public int getTierPriority() {
		// priority of this loader 
		return 99;
	}

	@Override
	public String getName() {
		return "Simple Shellcode Source Loader";
	}

	private FlatProgramAPI flatapi;
	
	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException
	{	
		// The List of load specs supported by this loader
		List<LoadSpec> loadSpecs = new ArrayList<>();
		
		// If the input filename is not a C source file then don't activate
		// this loader
		if (!provider.getName().endsWith(".c")) {
			return loadSpecs;
		}
		
		// Use the same list as the raw binary loader, which is basically any possible loadspec
		// Since this has the lowest priority, a more specific loader will be presented
		// to the user if one exists.
		List<LanguageDescription> languageDescriptions =
			getLanguageService().getLanguageDescriptions(false);
		for (LanguageDescription languageDescription : languageDescriptions) {
			
			Collection<CompilerSpecDescription> compilerSpecDescriptions =
				languageDescription.getCompatibleCompilerSpecDescriptions();
			
			for (CompilerSpecDescription compilerSpecDescription : compilerSpecDescriptions) {
				LanguageCompilerSpecPair lcs =
					new LanguageCompilerSpecPair(languageDescription.getLanguageID(),
						compilerSpecDescription.getCompilerSpecID());
				
				loadSpecs.add(new LoadSpec(this, 0, lcs, false));
			}
		}
		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException
	{
		flatapi = new FlatProgramAPI(program);

		try {
			monitor.setMessage( "Shellcode Source Loader: Starting loading" );
	
			// set up the regex matcher
			CharSequence provider_char_seq = new String(provider.readBytes(0,  provider.length()), "UTF-8");
			Pattern p = Pattern.compile("\\\\x[0-9a-fA-F]{1,2}");
			Matcher m = p.matcher(provider_char_seq);
			
			// Determine how many matches (shellcode bytes) were found so we can correctly
			// size the memory region, then reset the matcher
			int match_count = 0;
			while (m.find()) {
				match_count++;
			}
			m.reset(); 

			byte[] shellcode = new byte[match_count];
			// convert the hex representation of bytes in the source code to actual
			// byte values in the binary we're creating in Ghidra
			int ii = 0;
			while (m.find()) {
				// strip out the \x
				String hex_digits = m.group().replaceAll("[^0-9a-fA-F]+", "");
				// parse what's left into an integer and cast it to a byte, then
				// set current byte in byte array to that value
				shellcode[ii++] = (byte)Integer.parseInt(hex_digits, 16);
			}
			
			// create the memory block and populate it with the shellcode
			Address start_addr = flatapi.toAddr(0x0);
			MemoryBlock block = flatapi.createMemoryBlock(
					"SHELLCODE", start_addr, shellcode, false);
			
			// make this memory block RX but not writeable
			block.setRead(true);
			block.setWrite(false);
			block.setExecute(true);

			// add the entry point at the start of the shellcode
			flatapi.addEntryPoint(start_addr);
			
			monitor.setMessage( "Shellcode Source Loader: Completed loading" );
		} catch (Exception e) {
			e.printStackTrace();
			throw new IOException("Failed to load shellcode"); 
		}
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram)
	{	
		// no options in this case
		List<Option> list = new ArrayList<Option>();
		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec,
			List<Option> options, Program program)
	{
		// don't need to validate options as there are none
		return null;
	}
}
