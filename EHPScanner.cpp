// 
// EhFolder scanner & extractor
// by Xan/Tenjoin
// 

#include <iostream>
#include <vector>
#include <map>
#include <string>
#include <filesystem>
#include <fstream>
#include "include/patterns.hpp"
#include "ElfHeader.h"
#include "EhFolderTypes.h"

bool bScanOnlyMode = false;
std::vector<off_t> gEHPOffsets;
std::vector<uint32_t> gEHPSizes;

std::map<EhpType, uintptr_t> gElfEHPOffsets;
std::map<EhpType, uint32_t> gElfEHPSizes;
std::map<EhpType, std::string> EhpTypeNames =
{
    {EHP_TYPE_CNAME, EHP_NAME_CNAME},
    {EHP_TYPE_INTERFACE, EHP_NAME_INTERFACE},
    {EHP_TYPE_RCPSET, EHP_NAME_RCPSET},
    {EHP_TYPE_LOAD_FL, EHP_NAME_LOAD_FL},
    {EHP_TYPE_SYSMSG, EHP_NAME_SYSMSG},
    {EHP_TYPE_PACKSET, EHP_NAME_PACKSET}
};

// we'll limit the size of the ELF file for unusual instances
// 128MB limit
#define ELF_SIZE_LIMIT 128 * 1024 * 1024 

#define EHP_MAGIC 0x504845
#define ELF_MAGIC 0x464C457F

namespace MIPSTools
{
    uintptr_t FindFirstJAL(uintptr_t start, uint32_t inscount)
    {
        for (int i = 0; i < inscount; i++)
        {
            uint32_t ins = *(uint32_t*)(start + (4 * i));

            if ((ins >> 26) == 3)
            {
                return start + (4 * i);
            }
        }

        return 0;
    }

    uintptr_t DiscoverPtr(uintptr_t start, uintptr_t* ptrLast)
    {
        uintptr_t ptrLUI = 0;
        uintptr_t ptrADD = start;

        // find the first LUI after ADDIU
        for (int i = 0; i < 10; i++)
        {
            uint32_t ins = *(uint32_t*)(ptrADD + (4 * i)) & 0xFFFF0000;
            if (ins == 0x3C050000)
            {
                ptrLUI = ptrADD + (4 * i);
                break;
            }
        }

        if (ptrLUI == NULL)
            return NULL;


        ptrADD = NULL;

        // find the first ADDIU after LUI
        for (int i = 0; i < 10; i++)
        {
            uint32_t ins = *(uint32_t*)(ptrLUI + (4 * i)) & 0xFFFF0000;
            if (ins == 0x24A50000)
            {
                ptrADD = ptrLUI + (4 * i);
                break;
            }
        }

        if (ptrADD == NULL)
            return NULL;

        uint32_t insLUI = *(uint32_t*)ptrLUI;
        uint32_t insADD = *(uint32_t*)ptrADD;

        // construct the ptr from the instructions
        uint32_t part1 = (insLUI & 0xFFFF);
        uint32_t part2 = (insADD & 0xFFFF);
        // TODO: check for negative numbers, this is a signed number
        if (part2 > 0x7FFF)
            part1 -= 1;
        part1 <<= 16;

        uintptr_t retVal = part1 | part2;

        *ptrLast = ptrADD;

        return retVal;
    }
}

int CheckELFMagic(std::filesystem::path inFilename)
{
    std::ifstream inFile;
    inFile.open(inFilename, std::ios::binary);

    if (!inFile.is_open())
    {
        std::cout << "ERROR: Can't open " << inFilename.string() << " for reading\n";
        std::cout << "Reason: " << strerror(errno) << '\n';
        return -1;
    }

    uint32_t magic;
    inFile.read((char*)&magic, sizeof(uint32_t));

    if (magic == ELF_MAGIC)
    {
        inFile.close();
        return 1;
    }

    inFile.close();
    return 0;
}

int ScanElfEHPs(char* elfBuffer, uintmax_t elfSize, std::map<EhpType, uintptr_t>* ehpOffsets, std::map<EhpType, uint32_t>* ehpSizes)
{
    bool bInTF6 = true;
    Elf32_Ehdr* elfHdr = (Elf32_Ehdr*)elfBuffer;
    if (elfHdr->e_phoff == 0)
        return -3;

    Elf32_Phdr* elfPhdr = (Elf32_Phdr*)((uintptr_t)elfBuffer + elfHdr->e_phoff);

    uint32_t hdrSize = elfPhdr->p_offset;

    uintptr_t ptrCode = (uintptr_t)&elfBuffer[hdrSize];

    pattern::SetGameBaseAddress(ptrCode, elfSize - hdrSize);

    // check if we're in Tag Force at all
    uintptr_t ptr_lYgSysDLFile_GetFileList_4998C = pattern::get_first("28 00 00 ? ? ? ? 60 01 06 ?", 0);
    if (ptr_lYgSysDLFile_GetFileList_4998C == 0)
        return -1;
    ptr_lYgSysDLFile_GetFileList_4998C += 7;
    uintptr_t ptr_ptr_YgSys_Ms_GetDirPath = MIPSTools::FindFirstJAL(ptr_lYgSysDLFile_GetFileList_4998C, 6);
    if (ptr_ptr_YgSys_Ms_GetDirPath == 0)
        return -1;

    // check if we're in TF6 or Special by pattern detect
    uintptr_t ptr_YgSys_InitApplication = pattern::get_first("FF BD 27 ? ? 05 3C 25 20 00 00 60 00 B0 AF 64 00 B1 AF", 0);
    if (ptr_YgSys_InitApplication == 0)
    {
        bInTF6 = false;
        // try again for TF1-5
        ptr_YgSys_InitApplication = pattern::get_first("FF BD 27 ? ? 05 3C 0C 00 BF AF 21 20 00 00", 0);
        if (ptr_YgSys_InitApplication == 0)
            return -1;
    }

    ptr_YgSys_InitApplication -= 1;

    // count up all calls to EhFolder_CreateFromMemory
    int numEHP = 0;

    // find the first JAL within next 10 instructions
    uintptr_t ptrFirstJAL = MIPSTools::FindFirstJAL(ptr_YgSys_InitApplication, 10);
    if (ptrFirstJAL == 0)
        return -2;

    uintptr_t ptrJAL = ptrFirstJAL - 4;
    do
    {
        // find the JAL within next 5 instructions
        ptrJAL = MIPSTools::FindFirstJAL(ptrJAL, 5);

        if (ptrJAL)
        {
            ptrJAL += sizeof(uint32_t);
            numEHP++;
        }
    } while (ptrJAL);

    if (numEHP == 0)
        return -2;

    // steal arguments for each call to EhFolder_CreateFromMemory (which should be pointers to the embedded EhFolders)
    uintptr_t ptrDiscoverStart = ptr_YgSys_InitApplication;
    uintptr_t EhpPtrs[10];
    uint32_t EhpRdSizes[10];
    for (int i = 0; i < numEHP; i++)
    {
        uintptr_t nextStart = 0;
        uintptr_t ptrEHP = MIPSTools::DiscoverPtr(ptrDiscoverStart, &nextStart);

        EhpPtrs[i] = ptrEHP + ptrCode;
        EhpRdSizes[i] = *(uint32_t*)(ptrEHP + ptrCode + sizeof(uint32_t));

        ptrDiscoverStart = nextStart;
    }

    // the first three are always in order
    (*ehpOffsets)[EHP_TYPE_CNAME] = EhpPtrs[EHP_TYPE_CNAME];
    (*ehpSizes)[EHP_TYPE_CNAME] = EhpRdSizes[EHP_TYPE_CNAME];

    (*ehpOffsets)[EHP_TYPE_INTERFACE] = EhpPtrs[EHP_TYPE_INTERFACE];
    (*ehpSizes)[EHP_TYPE_INTERFACE] = EhpRdSizes[EHP_TYPE_INTERFACE];

    (*ehpOffsets)[EHP_TYPE_RCPSET] = EhpPtrs[EHP_TYPE_RCPSET];
    (*ehpSizes)[EHP_TYPE_RCPSET] = EhpRdSizes[EHP_TYPE_RCPSET];

    if (numEHP < 6)
    {
        bool bInTF1 = false;

        // now we have to check in which TF game we're in
        // TF1 doesn't have the "packset" EhFolder, while TF4+ don't have "load_fl"

        // the last one in TF1 is always sysmsg, so we'll check for that
        uintptr_t ptrLastEHP = EhpPtrs[numEHP - 1];

        // check the first filename of the last EHP
        // get the pointer of the first filename
        char* EHPFirstFileName = (char*)((*(uint32_t*)(ptrLastEHP + 0x10)) + ptrLastEHP);

        if (strstr(EHPFirstFileName, "sysmsg"))
            bInTF1 = true;

        if (bInTF1)
        {
            (*ehpOffsets)[EHP_TYPE_LOAD_FL] = EhpPtrs[EHP_TYPE_LOAD_FL];
            (*ehpSizes)[EHP_TYPE_LOAD_FL] = EhpRdSizes[EHP_TYPE_LOAD_FL];

            (*ehpOffsets)[EHP_TYPE_SYSMSG] = EhpPtrs[EHP_TYPE_SYSMSG];
            (*ehpSizes)[EHP_TYPE_SYSMSG] = EhpRdSizes[EHP_TYPE_SYSMSG];
        }
        else
        {
            (*ehpOffsets)[EHP_TYPE_SYSMSG] = EhpPtrs[3];
            (*ehpSizes)[EHP_TYPE_SYSMSG] = EhpRdSizes[3];

            (*ehpOffsets)[EHP_TYPE_PACKSET] = EhpPtrs[4];
            (*ehpSizes)[EHP_TYPE_PACKSET] = EhpRdSizes[4];
        }
    }
    else
    {
        // these are in order of TF2 and 3
        (*ehpOffsets)[EHP_TYPE_LOAD_FL] = EhpPtrs[EHP_TYPE_LOAD_FL];
        (*ehpSizes)[EHP_TYPE_LOAD_FL] = EhpRdSizes[EHP_TYPE_LOAD_FL];

        (*ehpOffsets)[EHP_TYPE_SYSMSG] = EhpPtrs[EHP_TYPE_SYSMSG];
        (*ehpSizes)[EHP_TYPE_SYSMSG] = EhpRdSizes[EHP_TYPE_SYSMSG];

        (*ehpOffsets)[EHP_TYPE_PACKSET] = EhpPtrs[EHP_TYPE_PACKSET];
        (*ehpSizes)[EHP_TYPE_PACKSET] = EhpRdSizes[EHP_TYPE_PACKSET];
    }

    for (int i = 0; i < EHP_TYPE_COUNT; i++)
    {
        if ((*ehpOffsets)[(EhpType)i])
        {
            std::cout << "EhFolder: " << EhpTypeNames[(EhpType)i] << "\t| off: 0x" << std::uppercase << std::hex << (*ehpOffsets)[(EhpType)i] - ptrCode + hdrSize << "\t| size: 0x" << std::uppercase << std::hex << (*ehpSizes)[(EhpType)i] << '\n';
        }
    }

    return 0;
}

int WriteElfEHPs(char* elfBuffer, std::filesystem::path outPath, std::map<EhpType, uintptr_t>* ehpOffsets, std::map<EhpType, uint32_t>* ehpSizes)
{
    bool bWrittenOnce = false;
    for (int i = 0; i < EHP_TYPE_COUNT; i++)
    {
        if ((*ehpOffsets)[(EhpType)i])
        {
            std::filesystem::path outFile = outPath / EhpTypeNames[(EhpType)i];
            std::ofstream ofile;

            std::cout << "Writing: " << outFile.string() << "\n";
            ofile.open(outFile, std::ios::binary);

            if (!ofile.is_open())
            {
                std::cout << "ERROR: Can't open " << outFile.string() << " for writing\n";
                std::cout << "Reason: " << strerror(errno) << '\n';
                return -1;
            }

            ofile.write((char*)(*ehpOffsets)[(EhpType)i], (*ehpSizes)[(EhpType)i]);
            
            ofile.flush();
            ofile.close();
            bWrittenOnce = true;
        }
    }
    if (!bWrittenOnce)
        return -1;

    return 0;
}

int MemLoadFile(std::filesystem::path inFilename, char** outBuffer, uintmax_t* outSize)
{
    std::ifstream inFile;
    inFile.open(inFilename, std::ios::binary);
    // TODO: maybe rewrite this with exception handling
    if (!inFile.is_open())
    {
        std::cout << "ERROR: Can't open " << inFilename.string() << " for reading\n";
        std::cout << "Reason: " << strerror(errno) << '\n';
        return -1;
    }

    uintmax_t fileSize = std::filesystem::file_size(inFilename);
    *outSize = fileSize;
    if (fileSize > ELF_SIZE_LIMIT)
    {
        std::cout << "WARNING: Detected large file size (>128MB). Reading sequentially...\n";
        inFile.close();
        return 1;
    }

    *outBuffer = (char*)malloc(fileSize);
    inFile.read(*outBuffer, fileSize);
    inFile.close();

    return 0;
}

int ScanEHPs(std::filesystem::path fName, std::vector<off_t>* ehpOffsets, std::vector<uint32_t>* ehpSizes)
{
    std::ifstream ifile;
    ifile.open(fName, std::ios::binary);
    if (!ifile.is_open())
    {
        std::cout << "ERROR: Can't open " << fName.string() << " for reading\n";
        std::cout << "Reason: " << strerror(errno) << '\n';
        return -1;
    }

    uint32_t readmagic = 0;
    uint32_t readsize = 0;

    while (!ifile.eof())
    {
        ifile.read((char*)&readmagic, sizeof(uint32_t));
        readmagic &= 0xFFFFFF;
        if (readmagic == EHP_MAGIC)
        {
            ifile.read((char*)&readsize, sizeof(uint32_t));
            off_t curOffset = static_cast<off_t>(ifile.tellg()) - (2 * sizeof(uint32_t));
            ehpOffsets->push_back(curOffset);
            ehpSizes->push_back(readsize);
            std::cout << "EhFolder: off: 0x" << std::uppercase << std::hex << curOffset << "\t| size: 0x" << std::uppercase << std::hex << readsize << '\n';
        }
    }

    ifile.close();

    if (ehpOffsets->size() == 0)
    {
        std::cout << "ERROR: Couldn't find any EhFolders!\n";
        return -2;
    }



    return 0;
}

int ExtractEHPs(std::filesystem::path fName, std::filesystem::path outPath, std::vector<off_t>* ehpOffsets, std::vector<uint32_t>* ehpSizes)
{
    std::ifstream ifile;
    ifile.open(fName, std::ios::binary);

    if (!ifile.is_open())
    {
        std::cout << "ERROR: Can't open " << fName.string() << " for reading\n";
        std::cout << "Reason: " << strerror(errno) << '\n';
        return -1;
    }

    for (int i = 0; i < ehpOffsets->size(); i++)
    {
        std::filesystem::path outFile = outPath / fName.filename();
        outFile += "_";
        outFile += std::to_string(i);
        outFile += ".ehp";
        
        std::cout << "Writing: " << outFile.string() << "\n";

        //fout = fopen(outFile.c_str(), "wb");
        std::ofstream ofile;
        ofile.open(outFile, std::ios::binary);
        if (!ofile.is_open())
        {
            std::cout << "ERROR: Can't open " << outFile.string() << " for writing\n";
            std::cout << "Reason: " << strerror(errno) << '\n';
            ifile.close();
            return -1;
        }

        char* filebuffer = (char*)malloc(ehpSizes->at(i));

        ifile.seekg(ehpOffsets->at(i));
        ifile.read(filebuffer, ehpSizes->at(i));
        ofile.write(filebuffer, ehpSizes->at(i));

        free(filebuffer);
        ofile.flush();
        ofile.close();
    }

    ifile.close();
    return 0;
}

int FileFlow(int argc, char* argv[])
{
    char** rdArgv = argv;
    int rdArgc = argc;

    if (!bScanOnlyMode)
    {
        if ((argv[1][0] == '-') && (argv[1][1] == 's'))
        {
            rdArgv = &argv[1];
            rdArgc -= 1;
            bScanOnlyMode = true;
        }
    }

    int errcode = ScanEHPs(rdArgv[1], &gEHPOffsets, &gEHPSizes);
    if (errcode)
        return errcode;

    if (bScanOnlyMode)
        return 0;

    if (rdArgc == 2)
    {
        std::filesystem::path outPath = rdArgv[1];
        return ExtractEHPs(rdArgv[1], outPath.parent_path(), &gEHPOffsets, &gEHPSizes);
    }

    return ExtractEHPs(rdArgv[1], rdArgv[2], &gEHPOffsets, &gEHPSizes);
}

int ElfFlow(char* elfBuffer, uintmax_t elfSize, int argc, char* argv[])
{
    int errcode = 0;

    errcode = ScanElfEHPs(elfBuffer, elfSize, &gElfEHPOffsets, &gElfEHPSizes);
    if (errcode)
    {
        if (errcode == -1)
        {
            std::cout << "Not a Tag Force PSP ELF!\n";
            std::cout << "Exiting ELF mode...\n";
            return FileFlow(argc, argv);
        }
        if (errcode == -2)
        {
            std::cout << "Couldn't find any calls to EhFolder_CreateFromMemory!\n";
            std::cout << "Exiting ELF mode...\n";
            return FileFlow(argc, argv);
        }
        if (errcode == -3)
        {
            std::cout << "Potentially invalid ELF! Program header is missing!\n";
            std::cout << "Exiting ELF mode...\n";
            return FileFlow(argc, argv);
        }
        return errcode;
    }

    if (bScanOnlyMode)
        return 0;

    if (argc == 2)
    {
        std::filesystem::path outPath = argv[1];
        return WriteElfEHPs(elfBuffer, outPath.parent_path(), &gElfEHPOffsets, &gElfEHPSizes);
    }

    return WriteElfEHPs(elfBuffer, argv[2], &gElfEHPOffsets, &gElfEHPSizes);
}



int main(int argc, char* argv[])
{
    std::cout << "EhFolder scanner\n\n";

    if (argc <= 1)
    {
        std::cout << "USAGE: " << argv[0] << " InFile [OutPath]\n";
        std::cout << "USAGE (scan only): " << argv[0] << " -s InFile\n";
        std::cout << "USAGE (force non-ELF mode): " << argv[0] << " -f InFile [OutPath]\n";
        std::cout << "USAGE (force non-ELF & scan): " << argv[0] << " -f -s InFile [OutPath]\n";
        return -5;
    }

    if ((argv[1][0] == '-') && (argv[1][1] == 'f'))
        return FileFlow(argc - 1, &argv[1]);

    int result = 0;
    char** rdArgv = argv;
    int rdArgc = argc;

    if ((argv[1][0] == '-') && (argv[1][1] == 's'))
    {
        rdArgv = &argv[1];
        rdArgc -= 1;
        bScanOnlyMode = true;
    }

    result = CheckELFMagic(rdArgv[1]);

    if (result < 0)
        return result;

    if (result > 0)
    {
        std::cout << "Detected an ELF file, going to ELF mode...\n";

        char* elfBuffer;
        uintmax_t elfSize;
        result = MemLoadFile(rdArgv[1], &elfBuffer, &elfSize);
        if (result < 0)
            return result;

        if (result == 0)
            return ElfFlow(elfBuffer, elfSize, rdArgc, rdArgv);

        std::cout << "Exiting ELF mode...\n";
    }

    return FileFlow(rdArgc, rdArgv);
}
