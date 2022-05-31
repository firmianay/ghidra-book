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
import java.util.*;

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
 * This loader Loads shellcode binaries into Ghidra, including setting an entry
 * point.
 */
public class SimpleShellcodeLoader extends AbstractLibrarySupportLoader {

    public LoaderTier getTier() {
        return LoaderTier.UNTARGETED_LOADER;
    }

    @Override
    public int getTierPriority() {
        return 101;
    }

    @Override
    public String getName() {
        return "Simple Shellcode Loader";
    }

    private FlatProgramAPI flatapi;

    @Override
    public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
        // The List of load specs supported by this loader
        List<LoadSpec> loadSpecs = new ArrayList<>();

        // Use the same list as the raw binary loader, which is basically any possible
        // loadspec
        // Since this has the lowest priority, a more specific loader will be presented
        // to the user if one exists.
        List<LanguageDescription> languageDescriptions = getLanguageService().getLanguageDescriptions(false);
        for (LanguageDescription languageDescription : languageDescriptions) {

            Collection<CompilerSpecDescription> compilerSpecDescriptions = languageDescription
                    .getCompatibleCompilerSpecDescriptions();

            for (CompilerSpecDescription compilerSpecDescription : compilerSpecDescriptions) {
                LanguageCompilerSpecPair lcs = new LanguageCompilerSpecPair(languageDescription.getLanguageID(),
                        compilerSpecDescription.getCompilerSpecID());

                loadSpecs.add(new LoadSpec(this, 0, lcs, false));
            }
        }
        return loadSpecs;
    }

    @Override
    protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program,
            TaskMonitor monitor, MessageLog log) throws CancelledException, IOException {
        flatapi = new FlatProgramAPI(program);
        try {
            monitor.setMessage("Simple Shellcode: Starting loading");

            // create the memory block we're going to load the shellcode into
            Address start_addr = flatapi.toAddr(0x0);
            MemoryBlock block = flatapi.createMemoryBlock("SHELLCODE", start_addr,
                    provider.readBytes(0, provider.length()), false);

            // make this memory block read/execute but not writable
            block.setRead(true);
            block.setWrite(false);
            block.setExecute(true);

            // set the entry point for the shellcode to the start address
            flatapi.addEntryPoint(start_addr);

            monitor.setMessage("Simple Shellcode: Completed loading");
        } catch (Exception e) {
            e.printStackTrace();
            throw new IOException("Failed to load shellcode");
        }
    }

    @Override
    public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec, DomainObject domainObject,
            boolean isLoadIntoProgram) {
        // no options
        List<Option> list = new ArrayList<Option>();
        return list;
    }

    @Override
    public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {
        // no options, so no need to validate
        return null;
    }
}
