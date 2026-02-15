package org.dihalt;

import ghidra.app.util.DomainObjectService;
import ghidra.app.util.Option;
import ghidra.app.util.exporter.Exporter;
import ghidra.app.util.exporter.ExporterException;
import ghidra.app.util.template.TemplateSimplifier;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

import ghidra.program.model.listing.CodeUnitFormat;
import ghidra.program.model.listing.CodeUnitFormatOptions;
import ghidra.program.model.listing.CodeUnitFormatOptions.ShowBlockName;
import ghidra.program.model.listing.CodeUnitFormatOptions.ShowNamespace;

import java.io.*;
import java.util.*;

public class MsxRomExporter extends Exporter {

    private static final String OPTION_INCLUDE_COMMENTS = "Include ASM remarks";
    private static final String OPTION_FILL_WITH_DB = "Fill gaps & data with db";
    private static final String OPTION_CUSTOM_LABELS = "Include custom labels";

    private boolean includeComments = true;
    private boolean fillWithDb = true;
    private boolean customLabels = true;

    private Map<String, Boolean> blockSelection = new LinkedHashMap<>();
    private Map<Address, String> exportedLabels = new TreeMap<>();
    private CodeUnitFormat cuFormat;

    public MsxRomExporter() {
        super("MSX ROM SJASM ASM exporter", "rom", new HelpLocation("", ""));
    }

    // =============================================================
    // Options
    // =============================================================

    @Override
    public List<Option> getOptions(DomainObjectService svc) {

        List<Option> opts = new ArrayList<>();

        opts.add(new Option(OPTION_INCLUDE_COMMENTS, includeComments, Boolean.class, ""));
        opts.add(new Option(OPTION_FILL_WITH_DB, fillWithDb, Boolean.class, ""));
        opts.add(new Option(OPTION_CUSTOM_LABELS, customLabels, Boolean.class, ""));

        // 🔥 Dynamic Memory Blocks
        Program program = (Program) svc.getDomainObject();
        if (program != null) {
            MemoryBlock[] blocks = program.getMemory().getBlocks();

            for (MemoryBlock block : blocks) {
                String name = "Export block: " + block.getName();

                // All set by default
                blockSelection.putIfAbsent(block.getName(), true);

                opts.add(new Option(
                        name,
                        blockSelection.get(block.getName()),
                        Boolean.class,
                        ""));
            }
        }

        return opts;
    }

    @Override
    public void setOptions(List<Option> options) {
        for (Option o : options) {
            String name = o.getName();

            if (name.startsWith("Export block: ")) {
                String blockName = name.substring("Export block: ".length());
                blockSelection.put(blockName, (Boolean) o.getValue());
                continue;
            }

            switch (o.getName()) {
                case OPTION_INCLUDE_COMMENTS -> includeComments = (Boolean) o.getValue();
                case OPTION_FILL_WITH_DB -> fillWithDb = (Boolean) o.getValue();
                case OPTION_CUSTOM_LABELS -> customLabels = (Boolean) o.getValue();
            }
        }
    }

    // =============================================================
    // Export
    // =============================================================

    @Override
    public boolean export(File file, DomainObject domainObj, AddressSetView addrSet, TaskMonitor monitor)
            throws ExporterException, IOException {

        if (!(domainObj instanceof Program program)) {
            throw new ExporterException("Only Program supported");
        }

        try {
            exportBinary(file, program);

            AddressSet selectedAddresses = new AddressSet();
            for (MemoryBlock block : program.getMemory().getBlocks()) {
                if (blockSelection.getOrDefault(block.getName(), true)) {
                    selectedAddresses.addRange(block.getStart(), block.getEnd());
                }
            }
            exportAssembly(changeExtension(file, ".asm"), program, addrSet, monitor);

            exportSymbols(file, program, selectedAddresses, monitor);

        } catch (MemoryAccessException e) {
            throw new ExporterException(e);
        }

        return true;
    }

    // =============================================================
    // BIN
    // =============================================================

    private void exportBinary(File f, Program program)
            throws IOException, MemoryAccessException {

        try (FileOutputStream fos = new FileOutputStream(f)) {
            for (MemoryBlock block : program.getMemory().getBlocks()) {
                if (!blockSelection.getOrDefault(block.getName(), true))
                    continue;
                if (!block.isInitialized())
                    continue;

                byte[] buf = new byte[(int) block.getSize()];
                block.getBytes(block.getStart(), buf);
                fos.write(buf);
            }
        }
    }

    // =============================================================
    // ASM
    // =============================================================

    private void exportAssembly(File asmFile, Program program,
            AddressSetView addrSet, TaskMonitor monitor)
            throws IOException {

        Listing listing = program.getListing();

        AddressSet addressSet = new AddressSet();

        for (MemoryBlock block : program.getMemory().getBlocks()) {
            if (blockSelection.getOrDefault(block.getName(), true)) {
                addressSet.addRange(block.getStart(), block.getEnd());
            }
        }

        AddressSetView set = addressSet;

        Address maxAddr = set.getMaxAddress();

        try (PrintWriter w = new PrintWriter(new FileWriter(asmFile))) {

            w.println("; MSX ROM SJASM export");
            w.println("    ORG 0x4000");
            w.println();

            Address last = set.getMinAddress();
            CodeUnitIterator it = listing.getCodeUnits(set, true);

            // Configure options to match your desired output.
            // - Set includeExtendedReferenceMarkup to false to avoid "HL=>" and just get
            // "(label)".
            // - Adjust other flags as needed (e.g., follow pointers for effective
            // addresses).
            CodeUnitFormatOptions formatOptions = new CodeUnitFormatOptions(
                    ShowBlockName.NEVER, // Or NON_LOCAL if you want block names in operands.
                    ShowNamespace.NON_LOCAL, // Adjust namespace visibility.
                    null, // No custom prefix.
                    true, // Include register variable markup.
                    true, // Include stack variable markup.
                    true, // Include inferred variable markup.
                    false, // Include extended reference markup? Set false to avoid "=>".
                    true, // Include scalar adjustment.
                    true, // Include library names in namespace.
                    true, // Follow referenced pointers? Set true for effective address resolution.
                    new TemplateSimplifier() // Default simplifier; disable if not needed.
            );
            cuFormat = new CodeUnitFormat(formatOptions);

            while (it.hasNext() && !monitor.isCancelled()) {

                CodeUnit cu = it.next();
                Address addr = cu.getAddress();

                if (fillWithDb && last.compareTo(addr) < 0) {
                    emitDbRange(w, program, last, addr);
                }

                if (cu instanceof Instruction i) {
                    emitInstruction(w, i, program);
                } else if (cu instanceof Data d) {
                    emitData(w, d, program);
                }

                Address end = cu.getMaxAddress();
                if (end.equals(maxAddr))
                    break;
                last = end.add(1);
            }

            if (fillWithDb && last.compareTo(maxAddr) < 0) {
                emitDbRange(w, program, last, maxAddr);
            }

            w.println();
            w.println("    END");
        }
    }

    // =============================================================
    // Emit helpers
    // =============================================================

    private void emitInstruction(PrintWriter w, Instruction instr, Program program) {

        Address addr = instr.getAddress();
        SymbolTable symtab = program.getSymbolTable();
        Listing listing = program.getListing();

        // 1. Get primary symbol if it exists (includes user labels, analysis labels,
        // etc.)
        Symbol primary = symtab.getPrimarySymbol(addr);
        String labelToPrint = null;

        if (primary != null) {
            // Real or analyzed labels (FUN_, ENTRY, etc.)
            labelToPrint = primary.getName(true); // without namespace prefix
        } else {
            // Only generate LAB_ if there are incoming references (like Ghidra does)
            ReferenceManager refMgr = program.getReferenceManager();
            ReferenceIterator refsTo = refMgr.getReferencesTo(addr);
            boolean hasIncomingRef = refsTo.hasNext(); // at least one incoming reference

            if (hasIncomingRef) {
                // Generate name like Ghidra: LAB_ram_XXXX or similar
                String space = addr.getAddressSpace().getName().toLowerCase();
                String offset = String.format("%04x", addr.getOffset());
                labelToPrint = "LAB_" + space + "_" + offset;
            }
            // If it's a function start but has no primary → rare, but covered
            else if (program.getFunctionManager().getFunctionAt(addr) != null) {
                String space = addr.getAddressSpace().getName().toLowerCase();
                String offset = String.format("%04x", addr.getOffset());
                labelToPrint = "FUN_" + space + "_" + offset;
            }
        }

        // Print ONLY if there is a valid label (avoids one per line)
        if (labelToPrint != null && !labelToPrint.isEmpty()) {
            w.println(labelToPrint + ":");
            exportedLabels.put(addr, labelToPrint);
        }

        // Mnemonic + operands
        String mnemonic = instr.getMnemonicString();
        StringBuilder sb = new StringBuilder("    " + mnemonic);

        // Initial separator after mnemonic (usually a space)
        String initialSep = instr.getSeparator(0);
        if (initialSep != null && !initialSep.isEmpty()) {
            sb.append(initialSep);
        } else {
            sb.append(" "); // force space if Ghidra doesn't provide it
        }

        int ops = instr.getNumOperands();
        for (int i = 0; i < ops; i++) {
            if (i > 0) {
                // Separator between operands: usually comma + space
                String sep = instr.getSeparator(i);
                if (sep != null && !sep.isEmpty()) {
                    sb.append(sep);
                } else {
                    sb.append(", ");
                }
            }

            // Get operand formatted by Ghidra
            String op = cuFormat.getOperandRepresentationString(instr, i);

            // Clean and normalize a bit (optional but recommended)
            op = op.trim(); // remove extra spaces
            // op = op.replace(" ", ""); // if you want to remove ALL internal spaces
            // (careful with "IX + 5")
            // op = op.toUpperCase(); // if you prefer uppercase registers

            sb.append(op);
        }

        // Final comment (if enabled)
        if (includeComments) {
            String c = listing.getComment(CommentType.EOL, instr.getAddress());
            if (c != null && !c.isBlank()) {
                // Align comment a bit nicer
                String line = sb.toString();
                int len = line.length();
                if (len < 40) {
                    sb.append(" ".repeat(40 - len)); // padding to ~column 40
                }
                sb.append("  ; ").append(c.trim());
            }
        }

        w.println(sb.toString());
    }

    private void emitData(PrintWriter w, Data data, Program program) {

        Address start = data.getAddress();
        Address max = start.getAddressSpace().getMaxAddress();

        int len = data.getLength();
        long available = max.subtract(start) + 1;
        if (available <= 0)
            return;

        int safeLen = (int) Math.min(len, available);
        try {
            emitDbRange(w, program, start, start.add(safeLen));
        } catch (Exception e) {
            Msg.info(this, "Exporting finished.");
        }
    }

    private void emitDbRange(PrintWriter w, Program program, Address start, Address end) {

        Memory mem = program.getMemory();
        Address cur = start;

        while (cur.compareTo(end) < 0) {

            w.print("    db ");
            int count = 0;

            while (count < 16 && cur.compareTo(end) < 0) {
                try {
                    w.printf("0x%02X", mem.getByte(cur) & 0xFF);
                } catch (MemoryAccessException e) {
                    w.print("??");
                }

                cur = cur.add(1);
                if (count < 15 && cur.compareTo(end) < 0)
                    w.print(",");
                count++;
            }
            w.println();
        }
    }

    private void exportSymbols(File baseFile, Program program, AddressSetView selectedSet, TaskMonitor monitor)
            throws IOException {

        File symFile = changeExtension(baseFile, ".sym");

        try (PrintWriter w = new PrintWriter(new FileWriter(symFile))) {
            w.println("; Symbol file for " + baseFile.getName());
            w.println("; Generated by Ghidra MSX ROM SJASM exporter (v12.0.1 compatible)");
            w.println("; Only symbols/labels in selected memory blocks");
            w.println();

            SymbolTable symtab = program.getSymbolTable();
            SymbolIterator symIt = symtab.getAllSymbols(true); // true - include dynamic symbols

            // predefined labels
            while (symIt.hasNext() && !monitor.isCancelled()) {
                Symbol sym = symIt.next();

                // Only symbols with source USER or ANALYSIS (we skip IMPORT, EXTERNAL for now)
                if (sym.getSource() != SourceType.USER_DEFINED &&
                        sym.getSource() != SourceType.ANALYSIS &&
                        sym.getSource() != SourceType.IMPORTED) {
                    continue;
                }

                Address addr = sym.getAddress();

                // Only if inside selected blocks
                if (!selectedSet.contains(addr)) {
                    continue;
                }

                // Address in hexadecimal (4 digits, no 0x)
                String addrStr = String.format("%04X", addr.getOffset());

                String name = sym.getName(true); // without namespace prefix

                // EOL comment if exists
                String comment = "";
                String eol = program.getListing().getComment(CommentType.EOL, addr);
                if (eol != null && !eol.isBlank()) {
                    comment = "  ; " + eol.trim().replace("\n", " ").replace("\r", "");
                }

                w.printf("%-24s EQU   0x%s%s%n", name, addrStr, comment);
            }

            // my own labels, custom labels
            if (customLabels) {
                w.println();
                w.println("; Custom labels");
                for (Map.Entry<Address, String> entry : exportedLabels.entrySet()) {
                    Address addr = entry.getKey();
                    String name = entry.getValue();

                    if (!selectedSet.contains(addr))
                        continue; // just in case

                    String addrStr = String.format("%04X", addr.getOffset());

                    // EOL comment if exists
                    String comment = "";
                    String eol = program.getListing().getComment(CommentType.EOL, addr);
                    if (eol != null && !eol.isBlank()) {
                        comment = "  ; " + eol.trim().replace("\n", " ").replace("\r", "");
                    }

                    w.printf("%-24s EQU   0x%s%s%n", name, addrStr, comment);
                }
            }

            w.println();
            w.println("; End of symbol file");
        }

        Msg.info(this, "Symbols exported to: " + symFile.getAbsolutePath());
    }

    // =============================================================
    // Utils
    // =============================================================
    private String getDisplayedLabel(Address addr, Program program) {
        SymbolTable symtab = program.getSymbolTable();
        Symbol primary = symtab.getPrimarySymbol(addr);

        if (primary != null) {
            // Real label (user, analysis, imported, etc.)
            return primary.getName(true); // true = no namespace prefix if global
        }

        // No primary symbol → generate automatic name like Ghidra does
        String spaceName = addr.getAddressSpace().getName().toLowerCase();
        String offsetHex = String.format("%04x", addr.getOffset()); // or %x if you prefer no leading zeros

        // Is it a function start?
        Function func = program.getFunctionManager().getFunctionAt(addr);
        if (func != null) {
            return "FUN_" + spaceName + "_" + offsetHex;
        }

        // Default: label (LAB_)
        // Note: in some cases Ghidra uses DAT_, SUB_, etc., but LAB_ is the most common
        // for jumps/references
        return "LAB_" + spaceName + "_" + offsetHex;
    }

    private boolean isLikelyRomBlock(MemoryBlock block) {
        long start = block.getStart().getOffset();
        String name = block.getName().toUpperCase();
        return start >= 0x4000 &&
                (name.contains("ROM") || name.contains("BANK") || name.contains("SLOT"));
    }

    private File changeExtension(File f, String ext) {
        String p = f.getAbsolutePath();
        int i = p.lastIndexOf('.');
        if (i > 0)
            p = p.substring(0, i);
        return new File(p + ext);
    }
}
