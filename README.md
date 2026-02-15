# GhidraMSX

This is a Ghidra extension for version 12.0.1 onwards, containing an MSX ROM Loader and an MSX Sjasm Assembler Exporter.

## Features

- **MSX ROM Loader**: 
  - Validates ROM header (starts with 'AB').
  - Validates ROM size (must be a multiple of 8KB).
  - Use `z80` processor with `default` variant.
  - Automatically creates memory blocks for BIOS (0x0000), ROM (0x4000), and RAM (0xC000).
  - Loads standard MSX symbols.
- **Sjasm Assembler Exporter**:
  - Exports the current program as an assembly source file compatible with Sjasm.
  - Exports a symbol file (`.sym`) containing user-defined and analysis symbols.

## Supported ROM Types

The loader supports plain ROMs starting from address `0x4000` (8KB, 16KB, 32KB) as well as several common MegaROM mappers:

- **PLAIN**: Standard ROMs without memory mappers.
- **KONAMI4**: Konami 8KB mapper.
- **KONAMI5**: Konami SCC 8KB mapper.
- **ASCII8**: ASCII 8KB mapper.
- **ASCII16**: ASCII 16KB mapper.

## Loader Options

When importing a file, the "MSX ROM Loader" offers the following option:

- **Rom/MegaRom type**: 
  - Allows you to specify the mapper type.
  - Defaults to an **auto-detected** value based on ROM content analysis.
  - You can override the detection by selecting a specific mapper from the list (PLAIN, ASCII16, ASCII8, KONAMI4, KONAMI5).

## Exporter Options

When exporting your program as "MSX ROM SJASM ASM exporter", the following options are available:

- **Include ASM remarks**: (Default: `true`) Adds end-of-line comments from the listing to the assembly output.
- **Fill gaps & data with db**: (Default: `true`) Exports data and unanalyzed areas as `db` directives.
- **Include custom labels**: (Default: `true`) Includes user-defined labels in the exported symbol file.
- **Export block: [Block Name]**: (Default: `true`) A dynamic list of checkboxes for each memory block in the program, allowing you to selectively include or exclude specific blocks from the export.

 btv
