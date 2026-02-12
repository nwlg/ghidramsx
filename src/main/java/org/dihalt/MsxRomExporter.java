package org.dihalt;

import ghidra.app.util.DomainObjectService;
import ghidra.app.util.Option;
import ghidra.app.util.exporter.Exporter;
import ghidra.app.util.exporter.ExporterException;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
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
    private static final String OPTION_CUSTOM_LABELS = "Include custom labels";

    private MegaRomType megaRomType = MegaRomType.PLAIN;
    private boolean includeComments = true;
    private boolean onlyRomBanks = false;
    private boolean fillWithDb = true;
    private boolean smartData = true;
    private boolean customLabels = true;

    private Map<String, Boolean> blockSelection = new LinkedHashMap<>();
    private Map<Address, String> exportedLabels = new TreeMap<>();

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
                case OPTION_MEGAROM_TYPE ->
                        megaRomType = MegaRomType.fromName(((String) o.getValue()).trim().toUpperCase());
                case OPTION_INCLUDE_COMMENTS -> includeComments = (Boolean) o.getValue();
                case OPTION_ONLY_ROM_BANKS -> onlyRomBanks = (Boolean) o.getValue();
                case OPTION_FILL_WITH_DB -> fillWithDb = (Boolean) o.getValue();
                case OPTION_SMART_DATA -> smartData = (Boolean) o.getValue();
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
            throw new RuntimeException(e);
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

        //AddressSetView set = (addrSet != null) ? addrSet : program.getMemory();

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
        SymbolTable symtab = program.getSymbolTable();
        Listing listing = program.getListing();

        // 1. Obtener primary symbol si existe (incluye user labels, analysis labels, etc.)
        Symbol primary = symtab.getPrimarySymbol(addr);
        String labelToPrint = null;

        if (primary != null) {
            // Etiquetas reales o analizadas (FUN_, ENTRY, etc.)
            labelToPrint = primary.getName(true);  // sin namespace prefix
        } else {
            // Solo generar LAB_ si realmente hay referencias entrantes (como hace Ghidra)
            ReferenceManager refMgr = program.getReferenceManager();
            ReferenceIterator refsTo = refMgr.getReferencesTo(addr);
            boolean hasIncomingRef = refsTo.hasNext();  // al menos una referencia entrante

            if (hasIncomingRef) {
                // Generar nombre como Ghidra: LAB_ram_XXXX o similar
                String space = addr.getAddressSpace().getName().toLowerCase();
                String offset = String.format("%04x", addr.getOffset());
                labelToPrint = "LAB_" + space + "_" + offset;
            }
            // Si es inicio de función pero no tiene primary → raro, pero cubrimos
            else if (program.getFunctionManager().getFunctionAt(addr) != null) {
                String space = addr.getAddressSpace().getName().toLowerCase();
                String offset = String.format("%04x", addr.getOffset());
                labelToPrint = "FUN_" + space + "_" + offset;
            }
        }

        // Imprimir SOLO si hay etiqueta válida (evita una por línea)
        if (labelToPrint != null && !labelToPrint.isEmpty()) {
            w.println(labelToPrint + ":");
            exportedLabels.put(addr, labelToPrint);
        }

        // Mnemonic + operandos
        String mnemonic = instr.getMnemonicString();
        StringBuilder sb = new StringBuilder("    " + mnemonic);

        int ops = instr.getNumOperands();
        if (ops > 0) sb.append(" ");

        for (int i = 0; i < ops; i++) {
            if (i > 0) sb.append(",");

            Reference ref = instr.getPrimaryReference(i);
            Address target = null;
            if (ref != null && ref.getToAddress() != null && !ref.getToAddress().equals(Address.NO_ADDRESS)) {
                target = ref.getToAddress();
            }

            boolean handled = false;
            if (target != null) {
                // Preferir etiqueta real si existe
                Symbol sym = symtab.getPrimarySymbol(target);
                if (sym != null && sym.getName().length() > 0) {
                    sb.append(sym.getName(true));
                    handled = true;
                } else {
                    // Si no hay primary, pero hay refs entrantes → usar LAB_
                    ReferenceIterator refsToTarget = program.getReferenceManager().getReferencesTo(target);
                    if (refsToTarget.hasNext()) {
                        String space = target.getAddressSpace().getName().toLowerCase();
                        String offset = String.format("%04x", target.getOffset());
                        sb.append("LAB_" + space + "_" + offset);
                        handled = true;
                    }
                }
            }

            if (!handled) {
                // Fallback a lo que Ghidra muestra por defecto
                sb.append(instr.getDefaultOperandRepresentation(i));
            }
        }

        // Comentario EOL
        if (includeComments) {
            String c = listing.getComment(CommentType.EOL, addr);
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

                // Solo símbolos con fuente USER o ANALYSIS (evitamos IMPORT, EXTERNAL por ahora)
                if (sym.getSource() != SourceType.USER_DEFINED &&
                        sym.getSource() != SourceType.ANALYSIS &&
                        sym.getSource() != SourceType.IMPORTED) {
                    continue;
                }

                Address addr = sym.getAddress();

                // Solo si está dentro de los bloques seleccionados
                if (!selectedSet.contains(addr)) {
                    continue;
                }

                // Dirección en hexadecimal (4 dígitos, sin 0x)
                String addrStr = String.format("%04X", addr.getOffset());

                String name = sym.getName(true);  // sin namespace prefix

                // Comentario EOL si existe
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

                    if (!selectedSet.contains(addr)) continue; // por si acaso

                    String addrStr = String.format("%04X", addr.getOffset());

                    // Comentario EOL si existe
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
            // Etiqueta real (user, analysis, imported, etc.)
            return primary.getName(true);  // true = sin prefijo de namespace si es global
        }

        // No hay símbolo primario → generar el nombre automático como hace Ghidra
        String spaceName = addr.getAddressSpace().getName().toLowerCase();
        String offsetHex = String.format("%04x", addr.getOffset());  // o %x si prefieres sin ceros

        // ¿Es inicio de función?
        Function func = program.getFunctionManager().getFunctionAt(addr);
        if (func != null) {
            return "FUN_" + spaceName + "_" + offsetHex;
        }

        // Por defecto: label (LAB_)
        // Nota: en algunos casos Ghidra usa DAT_, SUB_, etc., pero LAB_ es el más común para jumps/referencias
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
        if (i > 0) p = p.substring(0, i);
        return new File(p + ext);
    }
}
