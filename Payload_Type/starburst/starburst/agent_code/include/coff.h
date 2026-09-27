#ifndef STARBURST_COFF_H
#define STARBURST_COFF_H

#include <stdint.h>

#pragma pack(push, 1)
struct COFF_FILE_HEADER {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
};

struct COFF_SECTION {
    char     Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
};

struct COFF_SYMBOL {
    union {
        char     ShortName[8];
        struct {
            uint32_t Zeroes;
            uint32_t Offset;
        } Name;
    };
    uint32_t Value;
    int16_t  SectionNumber;
    uint16_t Type;
    uint8_t  StorageClass;
    uint8_t  NumberOfAuxSymbols;
};

struct COFF_RELOCATION {
    uint32_t VirtualAddress;
    uint32_t SymbolTableIndex;
    uint16_t Type;
};
#pragma pack(pop)

#ifndef IMAGE_REL_AMD64_ADDR64
#define IMAGE_REL_AMD64_ADDR64   0x0001
#endif
#ifndef IMAGE_REL_AMD64_ADDR32NB
#define IMAGE_REL_AMD64_ADDR32NB 0x0003
#endif
#ifndef IMAGE_REL_AMD64_REL32
#define IMAGE_REL_AMD64_REL32    0x0004
#endif
#ifndef IMAGE_REL_AMD64_REL32_1
#define IMAGE_REL_AMD64_REL32_1  0x0005
#endif
#ifndef IMAGE_REL_AMD64_REL32_2
#define IMAGE_REL_AMD64_REL32_2  0x0006
#endif
#ifndef IMAGE_REL_AMD64_REL32_3
#define IMAGE_REL_AMD64_REL32_3  0x0007
#endif
#ifndef IMAGE_REL_AMD64_REL32_4
#define IMAGE_REL_AMD64_REL32_4  0x0008
#endif
#ifndef IMAGE_REL_AMD64_REL32_5
#define IMAGE_REL_AMD64_REL32_5  0x0009
#endif

#endif
