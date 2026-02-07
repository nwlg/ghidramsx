package org.dihalt;

import ghidra.app.util.DomainObjectService;
import ghidra.app.util.Option;
import ghidra.app.util.exporter.Exporter;
import ghidra.app.util.exporter.ExporterException;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

import java.io.*;
import java.util.*;

public class MsxRomExporter extends Exporter {

    private static final String OPTION_MEGAROM_TYPE = "MegaROM Type";
    private static final String OPTION_INCLUDE_COMMENTS = "Include ASM remarks";
    private static final String OPTION_ONLY_ROM_BANKS = "Export only ROM banks";
    private static final String OPTION_FILL_WITH_DB = "Fill gaps & data with db";
    private static final String OPTION_SMART_DATA = "Smart data representation";

    private MegaRomType megaRomType = MegaRomType.PLAIN;
    private boolean includeComments = true;
    private boolean onlyRomBanks = false;
    private boolean fillWithDb = true;
    private boolean smartData = true;

    public MsxRomExporter() {
        super("MSX ROM SJASM ASM exporter", "rom", new HelpLocation("", ""));
    }

    // =============================================================
    // Options
    // =============================================================

    @Override
    public List<Option> getOptions(DomainObjectService svc) {

        List<Option> opts = new ArrayList<>();

        opts.add(new Option(
                OPTION_MEGAROM_TYPE,
                megaRomType.getDescription(),
                String.class,
                MsxRomLoader.MEGAROMTYPES_LIST_STRING));

        opts.add(new Option(OPTION_INCLUDE_COMMENTS, includeComments, Boolean.class, ""));
        opts.add(new Option(OPTION_ONLY_ROM_BANKS, onlyRomBanks, Boolean.class, ""));
        opts.add(new Option(OPTION_FILL_WITH_DB, fillWithDb, Boolean.class, ""));
        opts.add(new Option(OPTION_SMART_DATA, smartData, Boolean.class, ""));

        return opts;
    }

    @Override
    public void setOptions(List<Option> options) {

        for (Option o : options) {
            switch (o.getName()) {
                case OPTION_MEGAROM_TYPE ->
                        megaRomType = MegaRomType.fromName(((String) o.getValue()).trim().toUpperCase());
                case OPTION_INCLUDE_COMMENTS -> includeComments = (Boolean) o.getValue();
                case OPTION_ONLY_ROM_BANKS -> onlyRomBanks = (Boolean) o.getValue();
                case OPTION_FILL_WITH_DB -> fillWithDb = (Boolean) o.getValue();
                case OPTION_SMART_DATA -> smartData = (Boolean) o.getValue();
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
        } catch (MemoryAccessException e) {
            throw new RuntimeException(e);
        }
        exportAssembly(changeExtension(file, ".asm"), program, addrSet, monitor);

        return true;
    }

    // =============================================================
    // BIN
    // =============================================================

    private void exportBinary(File f, Program program)
            throws IOException, MemoryAccessException {

        try (FileOutputStream fos = new FileOutputStream(f)) {
            for (MemoryBlock block : program.getMemory().getBlocks()) {
                if (onlyRomBanks && !isLikelyRomBlock(block)) continue;
                if (!block.isInitialized()) continue;

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
        AddressSetView set = (addrSet != null) ? addrSet : program.getMemory();
        Address maxAddr = set.getMaxAddress();

        try (PrintWriter w = new PrintWriter(new FileWriter(asmFile))) {

            w.println("; MSX ROM SJASM export");
            w.println("    ORG 0x4000");
            w.println();

            Address last = set.getMinAddress();
            CodeUnitIterator it = listing.getCodeUnits(set, true);

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
                if (end.equals(maxAddr)) break;
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
        Symbol s = program.getSymbolTable().getPrimarySymbol(addr);
        //        if (s != null && !s.getName().startsWith("FUN_") && !s.getName().startsWith("LAB_")) {  // opcional: filtra LAB_ si no te gustan
        if ( s != null ) {
            w.println(s.getName() + ":");
        }

        String mnemonic = instr.getMnemonicString();
        StringBuilder sb = new StringBuilder("    " + mnemonic);

        int ops = instr.getNumOperands();
        if (ops > 0) sb.append(" ");

        SymbolTable symtab = program.getSymbolTable();

        for (int i = 0; i < ops; i++) {

            if (i > 0) sb.append(",");

            // 1. Intentamos obtener la referencia primaria del operando (la más importante)
            Reference ref = instr.getPrimaryReference(i);
            if (ref != null && ref.getToAddress() != null && !ref.getToAddress().equals(Address.NO_ADDRESS)) {
                Address target = ref.getToAddress();
                Symbol sym = symtab.getPrimarySymbol(target);
                if (sym != null && sym.getName().length() > 0) {
                    sb.append(sym.getName());
                    continue;
                }
            }

            // 2. Si no hay referencia primaria útil → fallback a getOpObjects
            Object[] objs = instr.getOpObjects(i);
            boolean handled = false;

            for (Object obj : objs) {
                if (obj instanceof Address a && !a.equals(Address.NO_ADDRESS)) {
                    Symbol sym = symtab.getPrimarySymbol(a);
                    if (sym != null && sym.getName().length() > 0) {
                        sb.append(sym.getName());
                        handled = true;
                        break;
                    }
                }
            }

            if (!handled) {
                // fallback al string por defecto de Ghidra
                sb.append(instr.getDefaultOperandRepresentation(i));
            }
        }

        // comentarios EOL
        if (includeComments) {
            String c = program.getListing().getComment(CommentType.EOL, addr);
            if (c != null && !c.isBlank()) {
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
        if (available <= 0) return;

        int safeLen = (int) Math.min(len, available);
        //Msg.info(this,"safeLen="+safeLen);
        try {
            emitDbRange(w, program, start, start.add(safeLen));
        } catch (Exception e) {
            Msg.info(this,"Exporting finished.");
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
                if (count < 15 && cur.compareTo(end) < 0) w.print(",");
                count++;
            }
            w.println();
        }
    }

    // =============================================================
    // Utils
    // =============================================================

    private boolean isLikelyRomBlock(MemoryBlock block) {
        long start = block.getStart().getOffset();
        String name = block.getName().toUpperCase();
        return start >= 0x4000 &&
                (name.contains("ROM") || name.contains("BANK") || name.contains("SLOT"));
    }

    private File changeExtension(File f, String ext) {
        String p = f.getAbsolutePath();
        int i = p.lastIndexOf('.');
        if (i > 0) p = p.substring(0, i);
        return new File(p + ext);
    }
}
