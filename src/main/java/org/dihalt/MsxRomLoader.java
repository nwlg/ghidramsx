package org.dihalt;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Collection;
import java.util.List;

public class MsxRomLoader extends AbstractLibrarySupportLoader {

    private static final long ROM_BASE = 0x4000;

    @Override
    public String getName() {
        return "MSX ROM Loader";
    }

    @Override
    public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
        Msg.info(this, "MSX: probing ROM");

        long size = provider.length();
        if ((provider.length() % 0x2000) != 0) { // 0x2000 = 8192 = 8K
            Msg.info(this, "MSX: Error. Rom size must be 8Kb multiple (" + size + " bytes)");
            return List.of();
        }

        try {
            // Read first two bytes
            byte b0 = provider.readByte(0);
            byte b1 = provider.readByte(1);

            if (b0 != 'A' || b1 != 'B') {
                Msg.info(this, "MSX: it's not a ROM, it doesn't start AB.");
                return List.of(); // unsupported
            }
        } catch (IOException e) {
            Msg.error(this, "MSX: Error reading ROM.", e);
            return List.of(); // unsupported
        }

        // if we are here it's because we recognize the file
        LanguageCompilerSpecPair pair = new LanguageCompilerSpecPair("z80:LE:16:default", "default");
        return List.of(new LoadSpec(this, 0, pair, true));
    }
/*
    @Override
    protected void load(
            Program program,
            ImporterSettings s)
            throws CancelledException, IOException {

        ByteProvider provider = s.provider();
        TaskMonitor monitor = s.monitor();
        MessageLog log = s.log();

        AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();

        monitor.setMessage("Loading MSX ROM...");
        MegaRomType megaRomType = getMegaromType(provider);
        if (megaRomType!=null) {
            Msg.info(this, "MSX: Megarom type guessed: " + megaRomType.getDescription());
        } else {
            Msg.info(this, "MSX: No megarom found!.");
        }

        // Build memory blocks
        long size = provider.length();
        Address start = space.getAddress(ROM_BASE);

        try {
            monitor.setMessage("Building BIOS block ...");
            program.getMemory().createUninitializedBlock(
                    "BIOS",
                    space.getAddress(0x0000),
                    0x4000,
                    false   // overlay?
            );

            monitor.setMessage("Building ROM block ...");
            program.getMemory().createInitializedBlock(
                    "ROM",
                    start,
                    provider.getInputStream(0),
                    0x4000,
//                    size,
                    monitor,
                    false
            );

            monitor.setMessage("Building RAM block ...");
            program.getMemory().createUninitializedBlock(
                    "RAM",
                    space.getAddress(0xC000),
                    0x4000,
                    false
            );

            MemoryBlock bios = program.getMemory().getBlock("BIOS");
            bios.setRead(true);
            bios.setWrite(false);
            bios.setExecute(true);

            MemoryBlock rom = program.getMemory().getBlock("ROM");
            rom.setRead(true);
            rom.setWrite(false);
            rom.setExecute(true);

            MemoryBlock ram = program.getMemory().getBlock("RAM");
            ram.setRead(true);
            ram.setWrite(true);
            ram.setExecute(true); // yeah, it could happen!

            bios.setName("BIOS");
            rom.setName("ROM");
            ram.setName("RAM");

        } catch (Exception e) {
            throw new IOException("Error building memory block", e);
        }

        Msg.info(this, "ROM loaded at 0x4000, size=" + size);
        log.appendMsg("ROM loaded at 0x4000 (" + size + " bytes)");

        if (size < 4) {
            log.appendMsg("ROM too small to contain entry point");
            return;
        }

        int entry = readLittleEndianWord(provider, 2);
        Address entryAddr = space.getAddress(entry);

        CodeUnit cu = program.getListing().getCodeUnitAt(entryAddr);
        if (cu != null) {
            cu.setComment(CommentType.EOL, "MSX cartridge entry point");
        }

        try {
            createEntryPoint(program, entryAddr);
        } catch (InvalidInputException e) {
            throw new RuntimeException(e);
        } catch (OverlappingFunctionException e) {
            throw new RuntimeException(e);
        }

        Msg.info(this, String.format("MSX entry point = 0x%04X", entry));

        // Does this really work?
        program.getOptions(Program.PROGRAM_INFO)
                .setBoolean("Show Block Name", true);

        program.getOptions(Program.PROGRAM_INFO)
                .setBoolean("Show Block Name Instead of Space", true);

        // Add msx_symbols.txt labels
        loadSymbolsFromResource(program, space, log);
    }
*/

    @Override
    protected void load(
            Program program,
            ImporterSettings s)
            throws CancelledException, IOException {

        ByteProvider provider = s.provider();
        TaskMonitor monitor = s.monitor();
        MessageLog log = s.log();

        AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();

        monitor.setMessage("Loading MSX ROM...");
        MegaRomType megaRomType = getMegaromType(provider);
        if (megaRomType != null) {
            Msg.info(this, "MSX: Megarom type guessed: " + megaRomType.getDescription());
        } else {
            Msg.info(this, "MSX: No megarom found!.");
        }

        // Build memory blocks
        long size = provider.length();

        // Determine page size and slot bases
        long page_size;
        long[] slot_bases;
        if (megaRomType == null) {
            page_size = size;
            slot_bases = new long[]{ROM_BASE};
        } else if (megaRomType == MegaRomType.ASCII16) {
            page_size = 0x4000;
            slot_bases = new long[]{0x4000, 0x8000};
        } else {
            page_size = 0x2000;
            slot_bases = new long[]{0x4000, 0x6000, 0x8000, 0xA000};
        }

        long num_banks = size / page_size;
        int num_subslots = slot_bases.length;

        try {
            monitor.setMessage("Building BIOS block ...");
            MemoryBlock bios = program.getMemory().createUninitializedBlock(
                    "BIOS",
                    space.getAddress(0x0000),
                    0x4000,
                    false   // overlay?
            );
            bios.setRead(true);
            bios.setWrite(false);
            bios.setExecute(true);

            monitor.setMessage("Building ROM slots ...");
            for (int j = 0; j < num_subslots; j++) {
                long slot_base = slot_bases[j];
                Address slot_addr = space.getAddress(slot_base);
                long block_size = page_size;

                // Initial bank: typically slot index for mega, 0 for non-mega
                int initial_bank = (megaRomType == null) ? 0 : j;
                if (initial_bank >= num_banks) {
                    initial_bank = 0;
                }

                // Create initial non-overlay block
                InputStream initial_is = provider.getInputStream(initial_bank * page_size);
                MemoryBlock initial_block = program.getMemory().createInitializedBlock(
                        "ROM_SLOT_" + Long.toHexString(slot_base).toUpperCase() + "_BANK_" + initial_bank,
                        slot_addr,
                        initial_is,
                        block_size,
                        monitor,
                        false
                );
                initial_block.setRead(true);
                initial_block.setWrite(false);
                initial_block.setExecute(true);

                // Create overlay blocks for other banks
                for (int b = 0; b < num_banks; b++) {
                    if (b == initial_bank) continue;

                    InputStream overlay_is = provider.getInputStream(b * page_size);
                    MemoryBlock overlay_block = program.getMemory().createInitializedBlock(
                            "ROM_SLOT_" + Long.toHexString(slot_base).toUpperCase() + "_BANK_" + b,
                            slot_addr,
                            overlay_is,
                            block_size,
                            monitor,
                            true  // overlay
                    );
                    overlay_block.setRead(true);
                    overlay_block.setWrite(false);
                    overlay_block.setExecute(true);
                }
            }

            monitor.setMessage("Building RAM block ...");
            MemoryBlock ram = program.getMemory().createUninitializedBlock(
                    "RAM",
                    space.getAddress(0xC000),
                    0x4000,
                    false
            );
            ram.setRead(true);
            ram.setWrite(true);
            ram.setExecute(true); // yeah, it could happen!

        } catch (Exception e) {
            throw new IOException("Error building memory block", e);
        }

        Msg.info(this, "ROM loaded at 0x4000, size=" + size);
        log.appendMsg("ROM loaded at 0x4000 (" + size + " bytes)");

        if (size < 4) {
            log.appendMsg("ROM too small to contain entry point");
            return;
        }

        int entry = readLittleEndianWord(provider, 2);
        Address entryAddr = space.getAddress(entry);

        CodeUnit cu = program.getListing().getCodeUnitAt(entryAddr);
        if (cu != null) {
            cu.setComment(CommentType.EOL, "MSX cartridge entry point");
        }

        try {
            createEntryPoint(program, entryAddr);
        } catch (InvalidInputException e) {
            throw new RuntimeException(e);
        } catch (OverlappingFunctionException e) {
            throw new RuntimeException(e);
        }

        Msg.info(this, String.format("MSX entry point = 0x%04X", entry));

        // Does this really work?
        program.getOptions(Program.PROGRAM_INFO)
                .setBoolean("Show Block Name", true);

        program.getOptions(Program.PROGRAM_INFO)
                .setBoolean("Show Block Name Instead of Space", true);

        // Add msx_symbols.txt labels
        loadSymbolsFromResource(program, space, log);
    }



    private static int readLittleEndianWord(ByteProvider p, int off) throws IOException {
        int lo = p.readByte(off) & 0xff;
        int hi = p.readByte(off + 1) & 0xff;
        return (hi << 8) | lo;
    }

    private static void createEntryPoint(Program program, Address addr)
            throws InvalidInputException, OverlappingFunctionException {
        program.getSymbolTable().addExternalEntryPoint(addr);
        program.getSymbolTable().createLabel(addr, "ENTRY", SourceType.IMPORTED);
    }

    private MegaRomType getMegaromType(ByteProvider provider) throws IOException {
        int[] megaRomCounts = new int[MegaRomType.values().length];
        // taken & adapted from OpenMSX
        for (int i = 16; i < provider.length(); i++) {
            if (provider.readByte(i) == 0x32) {
                int value = (provider.readByte(i + 1) & 0xFF) + ((provider.readByte(i + 2) & 0xFF) << 8);
                switch (value) {
                    case 0x5000:
                    case 0x9000:
                    case 0xb000:
                        megaRomCounts[MegaRomType.KONAMI5.ordinal()]++;
                        break;
                    case 0x4000:
                    case 0x8000:
                    case 0xa000:
                        megaRomCounts[MegaRomType.KONAMI4.ordinal()]++;
                        break;
                    case 0x6800:
                    case 0x7800:
                        megaRomCounts[MegaRomType.ASCII8.ordinal()]++;
                        break;
                    case 0x6000:
                        megaRomCounts[MegaRomType.KONAMI4.ordinal()]++;
                        megaRomCounts[MegaRomType.ASCII8.ordinal()]++;
                        megaRomCounts[MegaRomType.ASCII16.ordinal()]++;
                        break;
                    case 0x7000:
                        megaRomCounts[MegaRomType.KONAMI5.ordinal()]++;
                        megaRomCounts[MegaRomType.ASCII8.ordinal()]++;
                        megaRomCounts[MegaRomType.ASCII16.ordinal()]++;
                        break;
                    case 0x77ff:
                        megaRomCounts[MegaRomType.ASCII16.ordinal()]++;
                        break;
                }
            }
        }
        int maxVal= 0;
        int maxIndex = 1000; // high dummy
        for (int i=0 ; i<megaRomCounts.length;i++) {
            if (maxVal<megaRomCounts[i]) {
                maxVal = megaRomCounts[i];
                maxIndex = i;
            }
        }
        if (maxIndex!=1000){
            return MegaRomType.values()[maxIndex];
        } else return null;
    }


    private void loadSymbolsFromResource(
            Program program,
            AddressSpace space,
            MessageLog log
    ) throws IOException {

        Msg.info(this,"MSX: loading msx_symbols.txt");
        InputStream is = getClass().getClassLoader()
                .getResourceAsStream("msx_symbols.txt");

        if (is == null) {
            String info = "MSX: msx_symbols.txt file not found.";
            log.appendMsg(info);
            Msg.info(this,info);
            return;
        }

        BufferedReader br = new BufferedReader(new InputStreamReader(is));
        String line;

        while ((line = br.readLine()) != null) {
            line = line.trim();

            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }

            String[] parts = line.split("\\s+");
            if (parts.length < 2) {
                continue;
            }

            long addrValue = Long.decode(parts[0]);
            String name = parts[1];

            Address addr = space.getAddress(addrValue);

            try {
                program.getSymbolTable().createLabel(
                        addr,
                        name,
                        SourceType.IMPORTED
                );
            } catch (Exception e) {
                log.appendMsg("Cannot create symbol " + name + " at " + parts[0]);
            }
        }
        br.close();
    }
}

