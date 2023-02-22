// EhFolder scanner & extractor
// by Xan/Tenjoin
// 

#include <iostream>
#include <vector>
#include <string>
using namespace std;

vector<off_t> ehpOffsets;
vector<uint32_t> ehpSizes;

void* filebuffer;

#define EHP_MAGIC 0x03504845

#if __GNUC__
#define path_separator "/"
#else
#define path_separator "\\"
#endif

int ScanEHPs(string fName)
{
    FILE* f = fopen(fName.c_str(), "rb");
    if (!f)
    {
        cout << "Can't open " << fName << " for reading\n";
        perror("");
        return -1;
    }

    uint32_t readmagic = 0;
    uint32_t readsize = 0;

    while (!feof(f))
    {
        fread(&readmagic, sizeof(uint32_t), 1, f);
        if (readmagic == EHP_MAGIC)
        {
            fread(&readsize, sizeof(uint32_t), 1, f);
            ehpOffsets.push_back(ftell(f) - (2 * sizeof(uint32_t)));
            ehpSizes.push_back(readsize);
            printf("EhFolder: 0x%X\tsize: 0x%X\n", ftell(f) - (2 * sizeof(uint32_t)), readsize);
        }
    }

    fclose(f);

    if (ehpOffsets.size() == 0)
    {
        cout << "Couldn't find any EhFolders!\n";
        return -2;
    }



    return 0;
}

int ExtractEHPs(string fName, string outPath)
{
    FILE* f = fopen(fName.c_str(), "rb");
    FILE* fout;

    if (!f)
    {
        cout << "Can't open " << fName << " for reading\n";
        perror("");
        return -1;
    }

    string outFile;
    string fName_Separate = fName;

    size_t found = fName_Separate.find_last_of("/\\");
    if (found != string::npos)
        fName_Separate = fName_Separate.substr(found + 1);

    for (int i = 0; i < ehpOffsets.size(); i++)
    {
        outFile = outPath + path_separator + fName_Separate + "_" + to_string(i) + ".ehp";
        cout << "Writing: " << outFile << "\n";

        fout = fopen(outFile.c_str(), "wb");
        if (!fout)
        {
            cout << "Can't open " << outFile << " for writing\n";
            perror("");
            return -3;
        }

        filebuffer = malloc(ehpSizes.at(i));
        fseek(f, ehpOffsets.at(i), SEEK_SET);
        fread(filebuffer, ehpSizes.at(i), 1, f);
        fwrite(filebuffer, ehpSizes.at(i), 1, fout);

        free(filebuffer);
        fclose(fout);
    }

    fclose(f);
    return 0;
}

int main(int argc, char* argv[])
{
    cout << "EhFolder scanner\n";

    if (argc <= 1)
    {
        cout << "USAGE: " << argv[0] << " InFile [OutPath]\n";
        cout << "USAGE (scan only): " << argv[0] << " -s InFile\n";
        return -5;
    }

    if ((argv[1][0] == '-') && (argv[1][1] == 's'))
        return ScanEHPs(argv[2]);

    int errcode = ScanEHPs(argv[1]);
    if (errcode)
        return errcode;

    if (argc == 2)
    {
        string outPath = argv[1];
        size_t found = outPath.find_last_of("/\\");

        if (found == string::npos)
            return ExtractEHPs(argv[1], ".");

        return ExtractEHPs(argv[1], outPath.substr(0, found));
    }

    return ExtractEHPs(argv[1], argv[2]);
}
