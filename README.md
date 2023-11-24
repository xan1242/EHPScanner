# EhFolder Scanner

This is an application designed to scan for and extract any EhFolder it finds.

The main purpose is to allow easy extraction of EhFolders out of Tag Force EBOOT files.

It supports autodetection of Tag Force EBOOT files and proper assignment of filenames.

## Usage

```
USAGE: ehpscanner InFile [OutPath]
USAGE (scan only): ehpscanner -s InFile
USAGE (force non-ELF mode): ehpscanner -f InFile [OutPath]
USAGE (force non-ELF & scan): ehpscanner -f -s InFile
```

- If you do not pass the OutPath, it'll use the input file's parent path as output


