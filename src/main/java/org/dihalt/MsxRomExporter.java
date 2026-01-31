package org.dihalt;

import ghidra.app.util.DomainObjectService;
import ghidra.app.util.Option;
import ghidra.app.util.exporter.Exporter;
import ghidra.app.util.exporter.ExporterException;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.listing.CommentType;

import java.io.*;
import java.util.ArrayList;
import java.util.List;

public class MsxRomExporter extends Exporter {

    private static final String OPTION_MEGAROM_TYPE = "MegaROM Type";
    private static final String OPTION_INCLUDE_COMMENTS = "Include ASM remarks";
    private static final String OPTION_ONLY_ROM_BANKS = "Export only ROM banks";

    private MegaRomType megaRomType = MegaRomType.PLAIN;
    private boolean includeComments = true;
    private boolean onlyRomBanks = false;

    public MsxRomExporter() {
        super(
                "MSX ROM SJasm ASM exporter",
                "rom",
                new HelpLocation("","")
        );
    }

    // =============================================================
    // REQUIRED by Exporter (Ghidra 12.0.1)
    // =============================================================

    @Override
    public List<Option> getOptions(
            DomainObjectService domainObjectService) {

        DomainObject domainObj = domainObjectService.getDomainObject();

        List<Option> options = new ArrayList<>();
        if (options == null) {
            options = new ArrayList<>();
        }

        String defaultType = megaRomType.getDescription();

        options.add(new Option(
                OPTION_MEGAROM_TYPE,
                defaultType,
                String.class,
                "MegaROM types: "
                        + MsxRomLoader.MEGAROMTYPES_LIST_STRING));

        options.add(new Option(
                OPTION_INCLUDE_COMMENTS,
                includeComments,
                Boolean.class,
                "Include EOL Ghidra comments on ASM listing"));

        options.add(new Option(
                OPTION_ONLY_ROM_BANKS,
                onlyRomBanks,
                Boolean.class,
                "Export just ROM blocks"));

        return options;
    }

    // =============================================================
    // Options
    // =============================================================

    @Override
    public void setOptions(List<Option> options)
            throws ghidra.app.util.OptionException {

        for (Option option : options) {
            String name = option.getName();
            Object value = option.getValue();

            if (OPTION_MEGAROM_TYPE.equals(name)) {
                String typeStr = ((String) value).trim().toUpperCase();
                MegaRomType type = MegaRomType.fromName(typeStr);
                if (type == null) {
                    throw new ghidra.app.util.OptionException(
                            "Invalid MegaROM type: " + typeStr);
                }
                megaRomType = type;

            } else if (OPTION_INCLUDE_COMMENTS.equals(name)) {
                includeComments = (Boolean) value;

            } else if (OPTION_ONLY_ROM_BANKS.equals(name)) {
                onlyRomBanks = (Boolean) value;
            }
        }

        Msg.info(this,
                "Applied options - MegaROM: " + megaRomType +
                        ", Comments: " + includeComments +
                        ", ROM binary: " + onlyRomBanks);
    }

    // =============================================================
    // Export
    // =============================================================

    @Override
    public boolean export(
            File file,
            DomainObject domainObj,
            AddressSetView addrSet,
            TaskMonitor monitor)
            throws ExporterException, IOException {

        if (!(domainObj instanceof Program)) {
            throw new ExporterException(
                    "Only Program can be exported");
        }

        Program program = (Program) domainObj;

        monitor.initialize(100);
        monitor.setMessage("Exporting MSX ROM + ASM...");

        File binFile = file;
        try {
            exportBinary(binFile, program, addrSet, monitor);
        } catch (MemoryAccessException e) {
            e.printStackTrace();
        }

        File asmFile = changeExtension(binFile, ".asm");
        exportAssembly(asmFile, program, addrSet, monitor);

        Msg.info(this,
                "MSX: Exported: " + binFile + " + " + asmFile);

        return true;
    }

    // =============================================================
    // BIN
    // =============================================================

    private void exportBinary(
            File binFile,
            Program program,
            AddressSetView addrSet,
            TaskMonitor monitor)
            throws IOException, MemoryAccessException {

        try (FileOutputStream fos = new FileOutputStream(binFile)) {

            Memory memory = program.getMemory();

            for (MemoryBlock block : memory.getBlocks()) {

                if (onlyRomBanks && !isLikelyRomBlock(block)) {
                    continue;
                }

                if (!block.isInitialized()) {
                    continue;
                }

                monitor.setMessage(
                        "Wrinting block: " + block.getName());

                byte[] bytes = new byte[(int) block.getSize()];
                block.getBytes(block.getStart(), bytes);
                fos.write(bytes);
            }
        }
    }

    // =============================================================
    // ASM
    // =============================================================

    private void exportAssembly(
            File asmFile,
            Program program,
            AddressSetView addrSet,
            TaskMonitor monitor)
            throws IOException {

        try (PrintWriter writer =
                     new PrintWriter(new FileWriter(asmFile))) {

            writer.println("; Exported from Ghidra for SJASM - MSX ROM");
            writer.println("; MegaROM type: " + megaRomType.getDescription());
            writer.println("    ORG     0x4000");
            writer.println();

            Listing listing = program.getListing();
            AddressSetView effectiveSet =
                    (addrSet != null) ? addrSet : program.getMemory();

            InstructionIterator instrIter =
                    listing.getInstructions(effectiveSet, true);

            while (instrIter.hasNext()) {

                Instruction instr = instrIter.next();
                Address addr = instr.getAddress();

                Symbol primary =
                        program.getSymbolTable()
                                .getPrimarySymbol(addr);

                if (primary != null &&
                        !primary.getName().startsWith("FUN_")) {
                    writer.println(primary.getName() + ":");
                }

                String asm = instr.toString();

                if (includeComments) {
                    String comment =
                            listing.getComment(
                                    CommentType.EOL, addr);
                    if (comment != null && !comment.isEmpty()) {
                        asm += "  ; " + comment;
                    }
                }

                writer.println("    " + asm);
            }

            writer.println();
            writer.println("    END");
        }
    }

    // =============================================================
    // Utils
    // =============================================================

    private boolean isLikelyRomBlock(MemoryBlock block) {
        String name = block.getName().toUpperCase();
        long start = block.getStart().getOffset();
        return start >= 0x4000 &&
                (name.contains("ROM")
                        || name.contains("SLOT")
                        || name.contains("BANK"));
    }

    private File changeExtension(File original, String newExt) {
        String path = original.getAbsolutePath();
        int dotIndex = path.lastIndexOf('.');
        if (dotIndex > 0) {
            path = path.substring(0, dotIndex);
        }
        return new File(path + newExt);
    }
}

