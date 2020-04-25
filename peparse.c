#include <stdio.h>
#include <windows.h>
#include <string.h>


IMAGE_DOS_HEADER dosHeader;
IMAGE_NT_HEADERS ntHeaders;
IMAGE_SECTION_HEADER sectionHeader;
int bytes_read;
int stringTableSize;
char buffer[100];
int numSections;
long stringTableAddr;
long position;
char* stringTableData;
FILE* file;

int main(int argc, char const *argv[])
{

    if (argc < 2) {
        printf("\nUsage: %s <PE File>\n\n", argv[0]);
        exit(0);
    }

    file = fopen(argv[1], "r");
    if (!file) {
        printf("Couldn't open specified file\n");
        exit(1);
    }
    bytes_read = fread(&dosHeader,1,sizeof(IMAGE_DOS_HEADER),file );
    if (!bytes_read) {
        printf("Couldn't read file\n");
        exit(1);
    }
    if (dosHeader.e_magic != 0x5a4d) {
        printf("Invalid DOS magic bytes: %x != %x\n", dosHeader.e_magic, 0x5a4d);
        exit(1);
    }
    printf("NT headers offset: %d\n", dosHeader.e_lfanew);
    fseek(file, dosHeader.e_lfanew, SEEK_SET);
    bytes_read = fread(&ntHeaders, 1, sizeof(IMAGE_NT_HEADERS), file);
    if (!bytes_read) {
        printf("Couldn't read file\n");
        exit(1);
    }
    numSections = ntHeaders.FileHeader.NumberOfSections;
    printf("Number of sections: %d\n", numSections);
    stringTableAddr = ntHeaders.FileHeader.PointerToSymbolTable + ntHeaders.FileHeader.NumberOfSymbols*18; // String table right after symbol table
    position = ftell(file); // Backup current position (beginning of sections header)
    fseek(file, stringTableAddr, SEEK_SET);
    fread(&stringTableSize,4,1, file);
    stringTableData = (char*)malloc(stringTableSize-4); // First 4 bytes are only the size
    fread(stringTableData, 1, stringTableSize-4, file);
    fseek(file, position, SEEK_SET); // Restore position
    for (int i=0; i<numSections; i++) {
        bytes_read = fread(&sectionHeader,1,sizeof(IMAGE_SECTION_HEADER), file);
        if (!bytes_read) {
            printf("Couldn't read file\n");
            exit(1);
        }
        int offset;
        if (sectionHeader.Name[0]=='/') {
            offset = atoi(sectionHeader.Name+1);
            strncpy(buffer,stringTableData+offset-4, 100); // Offset includes the 4 beginning bytes, the size
        }
        else {
            strncpy(buffer, sectionHeader.Name, 8);
            buffer[8] = '\0';
        }
        printf("Section %d: %s\n", i, buffer);
        printf("--------------\n");
        printf("VirtualAddress: %x\n", sectionHeader.VirtualAddress);
        printf("VirtualSize: %x\n", sectionHeader.Misc.VirtualSize);
        printf("--------------\n\n");
    }
    free(stringTableData);
    return 0;
}
