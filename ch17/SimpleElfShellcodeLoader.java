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
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.ElfDataType;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.LoaderTier;
import ghidra.app.util.opinion.QueryOpinionService;
import ghidra.app.util.opinion.QueryResult;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.DomainObject;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Pointer32DataType;
import ghidra.program.model.lang.CompilerSpecDescription;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.Endian;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.lang.LanguageDescription;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class SimpleELFShellcodeLoader extends AbstractLibrarySupportLoader {

   public LoaderTier getTier() {
      return LoaderTier.GENERIC_TARGET_LOADER;
   }
   
   private FlatProgramAPI flatAPI;
   
   private final long LOAD_BASE        = 0x10000000;
   
   // See the ELF header format (e.g., at https://en.wikipedia.org/wiki/Executable_and_Linkable_Format)
   // Set up constants for ELF header format
   // We don't use the Program header (although it is in the samplebinary)
   // We assume there are no Section Headers for this example.
   
   private final byte[] ELF_MAGIC = {0x7f, 0x45, 0x4c, 0x46};
   private final long EH_MAGIC_OFFSET     = 0x00;
   private final long EH_MAGIC_LEN        = 4;
   
   private final long EH_CLASS_OFFSET     = 0x04;
   private final byte EH_CLASS_32BIT      = 0x01;
   
   private final long EH_DATA_OFFSET      = 0x05;
   private final byte EH_DATA_LITTLE_ENDIAN= 0x01;
   
   private final long EH_ETYPE_OFFSET     = 0x10;
   private final long EH_ETYPE_LEN        = 0x02;
   private final short EH_ETYPE_EXEC      = 0x02;
   
   private final long EH_EMACHINE_OFFSET  = 0x12;
   private final long EH_EMACHINE_LEN     = 0x02;
   private final short EH_EMACHINE_X86    = 0x03;
   
   private final long EH_EFLAGS_OFFSET    = 0x24;
   private final long EN_EFLAGS_LEN       = 4;
   
   private final long EH_EEHSIZE_OFFSET   = 0x28;
   private final long EH_PHENTSIZE_OFFSET = 0x2A;
   private final long EH_PHNUM_OFFSET     = 0x2C;
   
   private short e_ehsize;
   private short e_phentsize;
   private short e_phnum;
   
   @Override
   public String getName() {
      return "Simple ELF Shellcode Loader";
   }
   
   @Override
   public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
      // The List of load specs supported by this loader
      List<LoadSpec> loadSpecs = new ArrayList<>();
      
      // determine if this is an ELF binary by looking for the magic numbers
      if (! Arrays.equals(provider.readBytes(EH_MAGIC_OFFSET, EH_MAGIC_LEN), ELF_MAGIC)) {
         // not an ELF
         return loadSpecs;
      }

      // get the ELF parameters for the bit width and endianness, and
      // make sure that they are reasonable
      byte ei_class = provider.readByte(EH_CLASS_OFFSET);
      byte ei_data = provider.readByte(EH_DATA_OFFSET);
      if ((ei_class != EH_CLASS_32BIT) || (ei_data != EH_DATA_LITTLE_ENDIAN)) {
         // not an ELF we can load
         return loadSpecs;
      }

      // determine if the architecture is something we can handle
      byte[] etyp = provider.readBytes(EH_ETYPE_OFFSET, EH_ETYPE_LEN);
      short e_type = ByteBuffer.wrap(etyp).order(ByteOrder.LITTLE_ENDIAN).getShort();
      byte[] emach = provider.readBytes(EH_EMACHINE_OFFSET, EH_EMACHINE_LEN);
      short e_machine = ByteBuffer.wrap(emach).order(ByteOrder.LITTLE_ENDIAN).getShort();
      if ((e_type != EH_ETYPE_EXEC) || (e_machine != EH_EMACHINE_X86)) {
         // not an ELF we can load
         return loadSpecs;
      }
      
      byte[] eflags = provider.readBytes(EH_EFLAGS_OFFSET, EN_EFLAGS_LEN);
      int e_flags = ByteBuffer.wrap(eflags).order(ByteOrder.LITTLE_ENDIAN).getInt();
      
      /* Ask the opinion service to give us matches with the following parameters:
       * 
       *   loaderName = <The name of this loader>
       *   primaryKey = The machine type as a string (so "3" in this x86 case)
       *   secondaryKey = The flags field as a string
       *   
       *   We get back a list of matching languages and compilers for our provided
       *   search parameters.  We can then limit that list farther if we want (as
       *   shown examples for delphi and SMM below).  The list is generated from
       *   the x86.ldefs and x86.opinion files
       */
      
      List<QueryResult> results =
            QueryOpinionService.query(getName(), Short.toString(e_machine),
                  Integer.toString(e_flags));
      for (QueryResult result : results) {
         CompilerSpecID cspec = result.pair.getCompilerSpec().getCompilerSpecID();
         if (cspec.toString().equals("borlanddelphi")) {
            // ignore anything created by Delphi
            continue;
         }

         String variant = result.pair.getLanguageDescription().getVariant();
         if (variant.equals("System Management Mode")) {
            // ignore anything where the variant is "System Management Mode"
            continue;
         }

         // valid load spec, so add it to the list
         loadSpecs.add(new LoadSpec(this, 0, result));
      }

      return loadSpecs;
   }

   @Override
   protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
         Program program, TaskMonitor monitor, MessageLog log)
         throws CancelledException, IOException
   {
      flatAPI = new FlatProgramAPI(program);
      
      try {
         monitor.setMessage(getName() + ": Starting loading" );
   
         // get some values from the header that we'll need during the load process
         byte[] ehsz = provider.readBytes(EH_EEHSIZE_OFFSET, 2);
         e_ehsize = 
             ByteBuffer.wrap(ehsz).order(ByteOrder.LITTLE_ENDIAN).getShort();
         byte[] phsz = provider.readBytes(EH_PHENTSIZE_OFFSET, 2);
         e_phentsize = 
             ByteBuffer.wrap(phsz).order(ByteOrder.LITTLE_ENDIAN).getShort();
         byte[] phnum = provider.readBytes(EH_PHNUM_OFFSET, 2);
         e_phnum = ByteBuffer.wrap(phnum).order(ByteOrder.LITTLE_ENDIAN).getShort();

         // create the memory block for the ELF header
         long hdr_size = e_ehsize + e_phentsize * e_phnum;
         Address hdr_start_adr = flatAPI.toAddr(LOAD_BASE);
         MemoryBlock hdr_block = 
             flatAPI.createMemoryBlock(".elf_header", hdr_start_adr, 
                                       provider.readBytes(0, hdr_size),
                                       false);
         
         // make this memory block read only
         hdr_block.setRead(true);
         hdr_block.setWrite(false);
         hdr_block.setExecute(false);
         
         // create the memory block for the text
         Address txt_start_adr = flatAPI.toAddr(LOAD_BASE + hdr_size);
         long txt_size = provider.length() - hdr_size;
         MemoryBlock txt_block =
             flatAPI.createMemoryBlock(".text", txt_start_adr, 
                                       provider.readBytes(hdr_size, txt_size),
                                       false);
         
         // make this memory block read & execute
         txt_block.setRead(true);
         txt_block.setWrite(false);
         txt_block.setExecute(true);
   
         flatAPI.createLabel(txt_start_adr, "shellcode", true);
         flatAPI.addEntryPoint(txt_start_adr);

         // Add structure to the ELF HEADER
         flatAPI.createData(hdr_start_adr, new ElfDataType());
         
         // Add a cross reference from the ELF header to the entrypoint
         Data d = flatAPI.getDataAt(hdr_start_adr).getComponent(0).getComponent(9);
         flatAPI.createMemoryReference(d, txt_start_adr, RefType.DATA);

         monitor.setMessage(getName() + ": Completed loading" );
      } catch (Exception e) {
         e.printStackTrace();
         throw new IOException("Failed to load shellcode");
      }
   }
   
   @Override
   public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
         DomainObject domainObject, boolean isLoadIntoProgram)
   {
      // no options
      List<Option> list = new ArrayList<Option>();
      return list;
   }

   @Override
   public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {
      // no options, so no need to validate them
      return null;
   }
}
