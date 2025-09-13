// stub.cpp
#include <intrin.h>
// Type definitions, because Windows
typedef unsigned char  BYTE;
typedef unsigned short WORD;
typedef unsigned long  DWORD;
typedef unsigned long long QWORD;
typedef void*  LPVOID;
typedef void*  HANDLE;
typedef const void* LPCVOID;
typedef long   BOOL;
typedef unsigned __int64 SIZE_T;
typedef void* HWND;
typedef const char* LPCSTR;
typedef unsigned int UINT;
typedef unsigned long long uint64_t;
#define WINAPI __stdcall
#define NTAPI  __stdcall
#define IMAGE_DIRECTORY_ENTRY_EXPORT          0
#define IMAGE_DIRECTORY_ENTRY_IMPORT          1
#define IMAGE_DIRECTORY_ENTRY_RESOURCE        2
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION       3
#define IMAGE_DIRECTORY_ENTRY_SECURITY        4
#define IMAGE_DIRECTORY_ENTRY_BASERELOC       5
#define IMAGE_DIRECTORY_ENTRY_DEBUG           6
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    7
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8
#define IMAGE_DIRECTORY_ENTRY_TLS             9
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11
#define IMAGE_DIRECTORY_ENTRY_IAT            12
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14
// Placeholder for the packer to patch
extern "C" volatile DWORD header_rva_placeholder = 0xDEADBEEF;
// PE structures we need
struct IMAGE_DOS_HEADER { WORD e_magic; WORD e_cblp; WORD e_cp; WORD e_crlc; WORD e_cparhdr; WORD e_minalloc; WORD e_maxalloc; WORD e_ss; WORD e_sp; WORD e_csum; WORD e_ip; WORD e_cs; WORD e_lfarlc; WORD e_ovno; WORD e_res[4]; WORD e_oemid; WORD e_oeminfo; WORD e_res2[10]; DWORD e_lfanew; };
struct IMAGE_FILE_HEADER { WORD Machine; WORD NumberOfSections; DWORD TimeDateStamp; DWORD PointerToSymbolTable; DWORD NumberOfSymbols; WORD SizeOfOptionalHeader; WORD Characteristics; };
struct IMAGE_DATA_DIRECTORY { DWORD VirtualAddress; DWORD Size; };
struct IMAGE_OPTIONAL_HEADER64 { WORD Magic; BYTE MajorLinkerVersion; BYTE MinorLinkerVersion; DWORD SizeOfCode; DWORD SizeOfInitializedData; DWORD SizeOfUninitializedData; DWORD AddressOfEntryPoint; DWORD BaseOfCode; QWORD ImageBase; DWORD SectionAlignment; DWORD FileAlignment; WORD MajorOperatingSystemVersion; WORD MinorOperatingSystemVersion; WORD MajorImageVersion; WORD MinorImageVersion; WORD MajorSubsystemVersion; WORD MinorSubsystemVersion; DWORD Win32VersionValue; DWORD SizeOfImage; DWORD SizeOfHeaders; DWORD CheckSum; WORD Subsystem; WORD DllCharacteristics; QWORD SizeOfStackReserve; QWORD SizeOfStackCommit; QWORD SizeOfHeapReserve; QWORD SizeOfHeapCommit; DWORD LoaderFlags; DWORD NumberOfRvaAndSizes; IMAGE_DATA_DIRECTORY DataDirectory[16]; };
struct IMAGE_NT_HEADERS64 { DWORD Signature; IMAGE_FILE_HEADER FileHeader; IMAGE_OPTIONAL_HEADER64 OptionalHeader; };
struct IMAGE_EXPORT_DIRECTORY { DWORD Characteristics; DWORD TimeDateStamp; WORD MajorVersion; WORD MinorVersion; DWORD Name; DWORD Base; DWORD NumberOfFunctions; DWORD NumberOfNames; DWORD AddressOfFunctions; DWORD AddressOfNames; DWORD AddressOfNameOrdinals; };
struct RUNTIME_FUNCTION { DWORD BeginAddress; DWORD EndAddress; DWORD UnwindData; };
struct IMAGE_LOAD_CONFIG_DIRECTORY64 { DWORD Size; DWORD TimeDateStamp; WORD MajorVersion; WORD MinorVersion; DWORD GlobalFlagsClear; DWORD GlobalFlagsSet; DWORD CriticalSectionDefaultTimeout; QWORD DeCommitFreeBlockThreshold; QWORD DeCommitTotalFreeThreshold; QWORD LockPrefixTable; QWORD MaximumAllocationSize; QWORD VirtualMemoryThreshold; QWORD ProcessAffinityMask; DWORD ProcessHeapFlags; WORD CSDVersion; WORD DependentLoadFlags; QWORD EditList; QWORD SecurityCookie; QWORD SEHandlerTable; QWORD SEHandlerCount; QWORD GuardCFCheckFunctionPointer; QWORD GuardCFDispatchFunctionPointer; QWORD GuardCFFunctionTable; QWORD GuardCFFunctionCount; DWORD GuardFlags; };
struct UNICODE_STRING { WORD Length; WORD MaximumLength; QWORD Buffer; };
struct LIST_ENTRY { struct LIST_ENTRY* Flink; struct LIST_ENTRY* Blink; };
struct LDR_DATA_TABLE_ENTRY { LIST_ENTRY InLoadOrderLinks; LIST_ENTRY InMemoryOrderLinks; LIST_ENTRY InInitOrderLinks; QWORD DllBase; QWORD EntryPoint; DWORD SizeOfImage; DWORD _pad; UNICODE_STRING FullDllName; UNICODE_STRING BaseDllName; };
struct PEB_LDR_DATA { DWORD Length; BYTE Initialized[4]; QWORD SsHandle; struct LIST_ENTRY InLoadOrderModuleList; };
struct PEB { BYTE Reserved1[0x10]; QWORD ImageBaseAddress; struct PEB_LDR_DATA* Ldr; };
// Our packed data structures
#pragma pack(push, 1)
struct StubTLS { DWORD callbacks_rva, num_callbacks, start_addr_rva, end_addr_rva, index_rva, callback_array_rva, zero_fill_size; };
struct PackedSection { DWORD rva; DWORD compressed_size; DWORD decompressed_size; DWORD virtual_size; DWORD characteristics; DWORD offset_in_blob; };
struct StubHeader { 
    DWORD magic; 
    DWORD num_sections; 
    DWORD original_entry_point; 
    QWORD image_base; 
    QWORD image_size; 
    DWORD has_tls; 
    StubTLS tls_info; 
    DWORD has_imports; 
    DWORD import_dir_rva; 
    DWORD import_dir_size; 
    DWORD has_relocs; 
    DWORD reloc_dir_rva; 
    DWORD reloc_dir_size; 
    DWORD has_load_config; 
    DWORD load_config_dir_rva; 
    DWORD load_config_dir_size; 
    DWORD has_resources; 
    DWORD resource_dir_rva; 
    DWORD resource_dir_size; 
    DWORD has_delay_imports;
    DWORD delay_import_rva;
    DWORD delay_import_size;
    DWORD seh_table_rva;
    DWORD seh_count;
    DWORD iat_rva;
    DWORD iat_size;
    DWORD exception_rva;
    DWORD exception_size;
    DWORD has_debug_dir;
    DWORD debug_rva;
    DWORD debug_size;
    DWORD has_security_dir;
    DWORD security_offset;
    DWORD security_size;
    PackedSection sections[32]; 
    BYTE compressed_data[1]; 
};
#pragma pack(pop)
// Tiny CRT replacements
extern "C" void* memset(void* dst, int val, size_t count) { 
    unsigned char* p = (unsigned char*)dst; 
    while (count--) *p++ = (unsigned char)val; 
    return dst; 
}
static int my_strcmp(const char* a, const char* b) { while (*a && (*a == *b)) { a++; b++; } return (unsigned char)(*a) - (unsigned char)(*b); }
static const char* my_strchr(const char* s, char c) { while (*s) { if (*s == c) return s; s++; } return 0; }
static void my_strncpy(char* dst, const char* src, size_t n) { while (n && *src) { *dst++ = *src++; n--; } while (n--) *dst++ = 0; }
static void my_strcpy(char* dst, const char* src) { while ((*dst++ = *src++)); }
static void my_strcat(char* dst, const char* src) { while (*dst) dst++; while ((*dst++ = *src++)); }
// LZSS decompressor, fast and furious
static DWORD lzss_decompress(const BYTE* in, DWORD in_size, BYTE* out, DWORD out_max) {
    DWORD in_pos = 0;
    DWORD out_pos = 0;
    BYTE flags = 0;
    int flag_count = 0;
    while (in_pos < in_size && out_pos < out_max) {
        if (flag_count == 0) {
            flags = in[in_pos++];
            flag_count = 8;
        }
        if (flags & 1) {
            if (in_pos < in_size && out_pos < out_max) {
                out[out_pos++] = in[in_pos++];
            }
        } else {
            if (in_pos + 1 >= in_size) break;
            WORD match = (in[in_pos] << 8) | in[in_pos + 1];
            in_pos += 2;
            DWORD dist = (match & 0xFFF) + 1;
            DWORD len  = (match >> 12) + 3;
            if (dist > out_pos || out_pos + len > out_max) break;
            BYTE* dst = &out[out_pos];
            const BYTE* src = dst - dist;
            if (dist >= 8) {
				while (len >= 8 && out_pos + 8 <= out_max) {
					*reinterpret_cast<uint64_t*>(dst) = *reinterpret_cast<const uint64_t*>(src);
					dst += 8; src += 8; out_pos += 8; len -= 8;
				}
			}
			while (len > 0 && out_pos < out_max) {
				out[out_pos] = out[out_pos - dist];
				out_pos++;
				len--;
			}
        }
        flags >>= 1;
        flag_count--;
    }
    return out_pos;
}
// Find kernel32 by walking the PEB
static QWORD find_kernel32() {
    PEB* peb = (PEB*)__readgsqword(0x60);
    if (!peb || !peb->Ldr) return 0;
    LIST_ENTRY* list = &peb->Ldr->InLoadOrderModuleList;
    for (LIST_ENTRY* entry = list->Flink; entry != list; entry = ((LDR_DATA_TABLE_ENTRY*)entry)->InLoadOrderLinks.Flink) {
        LDR_DATA_TABLE_ENTRY* mod = (LDR_DATA_TABLE_ENTRY*)entry;
        UNICODE_STRING* name = &mod->BaseDllName;
        if (name->Buffer) {
            wchar_t* wbuf = (wchar_t*)name->Buffer;
            const wchar_t target[] = L"KERNEL32.DLL";
            int i = 0;
            while (wbuf[i] && target[i]) {
                wchar_t c1 = (wbuf[i] >= L'a' && wbuf[i] <= L'z') ? wbuf[i] - 32 : wbuf[i];
                wchar_t c2 = target[i];
                if (c1 != c2) break;
                i++;
            }
            if (!target[i]) return mod->DllBase;
        }
    }
    return 0;
}
// Find kernelbase, because Windows
static QWORD find_kernelbase() {
    PEB* peb = (PEB*)__readgsqword(0x60);
    if (!peb || !peb->Ldr) return 0;
    LIST_ENTRY* list = &peb->Ldr->InLoadOrderModuleList;
    for (LIST_ENTRY* entry = list->Flink; entry != list; entry = ((LDR_DATA_TABLE_ENTRY*)entry)->InLoadOrderLinks.Flink) {
        LDR_DATA_TABLE_ENTRY* mod = (LDR_DATA_TABLE_ENTRY*)entry;
        UNICODE_STRING* name = &mod->BaseDllName;
        if (name->Buffer) {
            wchar_t* wbuf = (wchar_t*)name->Buffer;
            const wchar_t target[] = L"KERNELBASE.DLL";
            int i = 0;
            while (wbuf[i] && target[i]) {
                wchar_t c1 = (wbuf[i] >= L'a' && wbuf[i] <= L'z') ? wbuf[i] - 32 : wbuf[i];
                wchar_t c2 = target[i];
                if (c1 != c2) break;
                i++;
            }
            if (!target[i]) return mod->DllBase;
        }
    }
    return 0;
}
// Find ntdll for the fancy stuff
static QWORD find_ntdll() {
    PEB* peb = (PEB*)__readgsqword(0x60);
    if (!peb || !peb->Ldr) return 0;
    LIST_ENTRY* list = &peb->Ldr->InLoadOrderModuleList;
    for (LIST_ENTRY* entry = list->Flink; entry != list; entry = ((LDR_DATA_TABLE_ENTRY*)entry)->InLoadOrderLinks.Flink) {
        LDR_DATA_TABLE_ENTRY* mod = (LDR_DATA_TABLE_ENTRY*)entry;
        UNICODE_STRING* name = &mod->BaseDllName;
        if (name->Buffer) {
            wchar_t* wbuf = (wchar_t*)name->Buffer;
            const wchar_t target[] = L"NTDLL.DLL";
            int i = 0;
            while (wbuf[i] && target[i]) {
                wchar_t c1 = (wbuf[i] >= L'a' && wbuf[i] <= L'z') ? wbuf[i] - 32 : wbuf[i];
                wchar_t c2 = target[i];
                if (c1 != c2) break;
                i++;
            }
            if (!target[i]) return mod->DllBase;
        }
    }
    return 0;
}
// Resolve APIs manually, no IAT for us
static QWORD get_proc_address(QWORD module, const char* target) {
    BYTE* base = (BYTE*)module;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != 0x5A4D) return 0;
    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(base + dos->e_lfanew);
    if (nt->Signature != 0x00004550) return 0;
    IMAGE_DATA_DIRECTORY expdir = nt->OptionalHeader.DataDirectory[0];
    if (!expdir.VirtualAddress || !expdir.Size) return 0;
    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(base + expdir.VirtualAddress);
    DWORD* names  = (DWORD*)(base + exp->AddressOfNames);
    WORD*  ords   = (WORD*)(base + exp->AddressOfNameOrdinals);
    DWORD* funcs  = (DWORD*)(base + exp->AddressOfFunctions);
    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        char* fname = (char*)(base + names[i]);
        if (my_strcmp(fname, target) == 0) {
            WORD ord = ords[i];
            DWORD fva = funcs[ord];
            BYTE* addr = base + fva;
            DWORD exp_start = expdir.VirtualAddress;
            DWORD exp_end   = exp_start + expdir.Size;
            if (fva >= exp_start && fva < exp_end) {
                const char* fwd = (const char*)addr;
                const char* dot = my_strchr(fwd, '.');
                if (!dot) return 0;
                char dll[128]; memset(dll, 0, sizeof(dll));
                char func[128]; memset(func, 0, sizeof(func));
                my_strncpy(dll, fwd, (size_t)(dot - fwd));
                my_strcpy(func, dot + 1);
                my_strcat(dll, ".dll");
                if (my_strcmp(target, "LoadLibraryA") == 0 || my_strcmp(target, "GetProcAddress") == 0) {
                    QWORD kbase = find_kernelbase();
                    if (kbase) return get_proc_address(kbase, target);
                }
                if ((dll[0] == 'a' || dll[0] == 'A') && (dll[1] == 'p' || dll[1] == 'P') && (dll[2] == 'i' || dll[2] == 'I') && dll[3] == '-') {
                    QWORD kbase = find_kernelbase();
                    if (kbase) return get_proc_address(kbase, func);
                }
                typedef QWORD (*LoadLibraryA_t)(const char*);
                QWORD k32 = find_kernel32();
                LoadLibraryA_t pLoadLibraryA = (LoadLibraryA_t)get_proc_address(k32, "LoadLibraryA");
                if (!pLoadLibraryA) return 0;
                QWORD newmod = pLoadLibraryA(dll);
                if (!newmod) return 0;
                return get_proc_address(newmod, func);
            }
            return (QWORD)addr;
        }
    }
    return 0;
}
// Convert section characteristics to memory protection
static DWORD char_to_protection(DWORD c) {
    BOOL executable = (c & 0x20000000) || (c & 0x20);  
    BOOL writable = (c & 0x80000000);                  
    BOOL readable = (c & 0x40000000) || executable || writable; 
    if (executable && writable) return 0x40;  
    if (executable && !writable) return 0x20; 
    if (!executable && writable) return 0x04; 
    return 0x02; 
}
// CFG stubs for when Windows gets paranoid
extern "C" void __stdcall cfg_check_icall_stub(void*) {}
extern "C" void* __stdcall cfg_dispatch_icall_stub(void* target, void*) { return target; }
#define RESOLVE_API(var, type, apiname) var = (type)get_proc_address(k32, apiname); if (!var && kbase) var = (type)get_proc_address(kbase, apiname); if (!var && pDbg) { pDbg("Failed to resolve " apiname); }
// The main unpacking party
static void do_unpack() {
    volatile int reached = 1;
    typedef BOOL   (*VirtualProtect_t)(LPVOID, SIZE_T, DWORD, DWORD*);
    typedef BOOL   (*FlushInstructionCache_t)(HANDLE, LPCVOID, SIZE_T);
    typedef HANDLE (*GetCurrentProcess_t)(void);
    typedef QWORD  (*LoadLibraryA_t)(const char*);
    typedef QWORD  (*GetProcAddress_t)(QWORD, const char*);
    typedef LPVOID (*VirtualAlloc_t)(LPVOID, SIZE_T, DWORD, DWORD);
    typedef HANDLE (*GetModuleHandleA_t)(LPCSTR);
    typedef int    (WINAPI *MessageBoxA_t)(HWND, LPCSTR, LPCSTR, UINT);
    typedef void (WINAPI *OutputDebugStringA_t)(LPCSTR);
    typedef BOOL (WINAPI *RtlAddFunctionTable_t)(RUNTIME_FUNCTION*, DWORD, QWORD);
    // Find our DLLs
    QWORD k32 = find_kernel32();
    QWORD kbase = find_kernelbase();
    QWORD ntdll = find_ntdll();
    OutputDebugStringA_t pDbg = (OutputDebugStringA_t)get_proc_address(k32, "OutputDebugStringA");
    if (pDbg) pDbg(k32 ? "[STUB] Found kernel32" : "[STUB] No kernel32");
    if (pDbg) pDbg(kbase ? "[STUB] Found kernelbase" : "[STUB] No kernelbase");
    if (pDbg) pDbg(ntdll ? "[STUB] Found ntdll" : "[STUB] No ntdll");
    if (!k32 && !kbase) return;
    LoadLibraryA_t pLoadLibraryA = 0;
    GetProcAddress_t pGetProcAddress = 0;
    if (k32) {
        pLoadLibraryA   = (LoadLibraryA_t)get_proc_address(k32, "LoadLibraryA");
        pGetProcAddress = (GetProcAddress_t)get_proc_address(k32, "GetProcAddress");
    }
    if ((!pLoadLibraryA || !pGetProcAddress) && kbase) {
        if (!pLoadLibraryA) pLoadLibraryA = (LoadLibraryA_t)get_proc_address(kbase, "LoadLibraryA");
        if (!pGetProcAddress) pGetProcAddress = (GetProcAddress_t)get_proc_address(kbase, "GetProcAddress");
    }
    if (k32 && pGetProcAddress) {
        pDbg = (OutputDebugStringA_t)pGetProcAddress(k32, "OutputDebugStringA");
    }
    if (pDbg) pDbg("STUB ENTERED");
#ifdef BUILD_STUB_EXE
    return;
#else
    // Resolve all the APIs we need
    VirtualProtect_t        pVirtualProtect;
    FlushInstructionCache_t pFlush;
    GetCurrentProcess_t     pGetCurrentProcess;
    VirtualAlloc_t          pVirtualAlloc;
    GetModuleHandleA_t      pGetModuleHandleA;
    RtlAddFunctionTable_t   pRtlAddFunctionTable = 0;
    RESOLVE_API(pVirtualProtect,        VirtualProtect_t,        "VirtualProtect");
    RESOLVE_API(pFlush,                 FlushInstructionCache_t, "FlushInstructionCache");
    RESOLVE_API(pGetCurrentProcess,     GetCurrentProcess_t,     "GetCurrentProcess");
    RESOLVE_API(pVirtualAlloc,          VirtualAlloc_t,          "VirtualAlloc");
    RESOLVE_API(pGetModuleHandleA,      GetModuleHandleA_t,      "GetModuleHandleA");
    if (ntdll) {
        pRtlAddFunctionTable = (RtlAddFunctionTable_t)get_proc_address(ntdll, "RtlAddFunctionTable");
    }
    if (!pRtlAddFunctionTable && k32) {
        pRtlAddFunctionTable = (RtlAddFunctionTable_t)get_proc_address(k32, "RtlAddFunctionTable");
    }
    if (!pVirtualProtect || !pFlush || !pGetCurrentProcess || !pVirtualAlloc || !pGetModuleHandleA) {
        if (pDbg) pDbg("RETURN: Failed resolving critical imports");
        return;
    }
    // Find our header
    BYTE* module_base = (BYTE*)pGetModuleHandleA(0);
    DWORD header_rva = header_rva_placeholder;
    StubHeader* header = (StubHeader*)(module_base + header_rva);
    if (header->magic != 0x58505553) {
        if (pDbg) pDbg("ERROR: Magic check failed");
        return;
    }
    if (pDbg) pDbg("SUCCESS: Magic check passed, proceeding with unpack");
    // Allocate new image
    BYTE* new_image = (BYTE*)pVirtualAlloc(0, (SIZE_T)header->image_size, 0x3000, 0x40);
    if (!new_image) return;
    // Decompress all sections
    const BYTE* blob = header->compressed_data;
    for (DWORD i = 0; i < header->num_sections; ++i) {
        const PackedSection& s = header->sections[i];
        BYTE* dest = new_image + s.rva;
        const BYTE* src = blob + s.offset_in_blob;
        DWORD written = lzss_decompress(src, s.compressed_size, dest, s.decompressed_size);
        if (s.decompressed_size < s.virtual_size) {
            __stosb(dest + s.decompressed_size, 0, s.virtual_size - s.decompressed_size);
        }
        if (pDbg) {
            auto hex32 = [](DWORD v, char* buf) {
                const char* hex = "0123456789ABCDEF";
                for (int i = 0; i < 8; i++) {
                    buf[7 - i] = hex[v & 0xF];
                    v >>= 4;
                }
                buf[8] = 0;
            };
            char rva[9], wrote[9], first[9];
            hex32(s.rva, rva);
            hex32(written, wrote);
            hex32(*(DWORD*)(new_image + s.rva), first);
            char dbg[128];
            int pos = 0;
            auto append = [&](const char* str) {
                while (*str && pos < (int)sizeof(dbg) - 1) {
                    dbg[pos++] = *str++;
                }
                dbg[pos] = '\0';
            };
            append("[STUB] Section ");
            append(rva);
            append(" wrote=");
            append(wrote);
            append(" first=");
            append(first);
            pDbg(dbg);
        }
    }
    // Resolve imports
    if (header->has_imports) {
        struct ImportDescriptor { DWORD OriginalFirstThunk; DWORD TimeDateStamp; DWORD ForwarderChain; DWORD Name; DWORD FirstThunk; };
        ImportDescriptor* desc = (ImportDescriptor*)(new_image + header->import_dir_rva);
        DWORD iat_start = 0xFFFFFFFF;
        DWORD iat_end = 0;
        ImportDescriptor* temp_desc = desc;
        while (temp_desc->Name) {
            if (temp_desc->FirstThunk < iat_start) iat_start = temp_desc->FirstThunk;
            QWORD* thunk = (QWORD*)(new_image + temp_desc->FirstThunk);
            while (*thunk) { thunk++; }
            DWORD thunk_end = (DWORD)((BYTE*)thunk - new_image) + sizeof(QWORD);
            if (thunk_end > iat_end) iat_end = thunk_end;
            temp_desc++;
        }
        if (iat_start != 0xFFFFFFFF && iat_end > iat_start) {
            DWORD iat_size = iat_end - iat_start;
            DWORD old_iat_prot = 0;
            pVirtualProtect(new_image + iat_start, iat_size, 0x04, &old_iat_prot);
        }
        while (desc->Name) {
            char* dll_name = (char*)(new_image + desc->Name);
            QWORD dll_base = pLoadLibraryA(dll_name);
            if (dll_base) {
                QWORD* thunk = (QWORD*)(new_image + desc->FirstThunk);
                QWORD* orig_thunk = desc->OriginalFirstThunk ? (QWORD*)(new_image + desc->OriginalFirstThunk) : thunk;
                while (*orig_thunk) {
                    if (*orig_thunk & 0x8000000000000000ULL) {
                        WORD ordinal = (WORD)(*orig_thunk & 0xFFFF);
                        *thunk = pGetProcAddress(dll_base, (const char*)(SIZE_T)ordinal);
                    } else {
                        struct ImportByName { WORD Hint; char Name[1]; };
                        ImportByName* ibn = (ImportByName*)(new_image + *orig_thunk);
                        *thunk = pGetProcAddress(dll_base, ibn->Name);
                    }
                    thunk++;
                    orig_thunk++;
                }
            }
            desc++;
        }
        BYTE* nt_headers = new_image + *(DWORD*)(new_image + 0x3C);
        DWORD* import_dir_entry = (DWORD*)(nt_headers + 0x90);
        *import_dir_entry = header->import_dir_rva;
        *(import_dir_entry + 1) = header->import_dir_size;
    }
    // Apply relocations if needed
    if (header->has_relocs && (QWORD)new_image != header->image_base) {
        QWORD delta = (QWORD)new_image - header->image_base;
        if (pDbg) pDbg("[STUB] Applying relocations due to base address difference");
        BYTE* reloc_data = new_image + header->reloc_dir_rva;
        BYTE* reloc_end = reloc_data + header->reloc_dir_size;
        while (reloc_data < reloc_end) {
            struct BaseRelocBlock { DWORD VirtualAddress; DWORD SizeOfBlock; };
            BaseRelocBlock* block = (BaseRelocBlock*)reloc_data;
            if (block->SizeOfBlock == 0) break;
            WORD* entries = (WORD*)(reloc_data + sizeof(BaseRelocBlock));
            DWORD num_entries = (block->SizeOfBlock - sizeof(BaseRelocBlock)) / sizeof(WORD);
            for (DWORD i = 0; i < num_entries; i++) {
                WORD entry = entries[i];
                WORD type = entry >> 12;
                WORD offset = entry & 0xFFF;
                if (type == 10) {
                    QWORD* addr = (QWORD*)(new_image + block->VirtualAddress + offset);
                    *addr += delta;
                }
            }
            reloc_data += block->SizeOfBlock;
        }
    }
    // Update PEB
    PEB* peb = (PEB*)__readgsqword(0x60);
    if (peb) {
        peb->ImageBaseAddress = (QWORD)new_image;
        if (pDbg) pDbg("[STUB] Updated PEB ImageBaseAddress");
    }
    // Handle TLS
    if (header->has_tls) {
        struct TlsDirectory { QWORD StartAddressOfRawData; QWORD EndAddressOfRawData; QWORD AddressOfIndex; QWORD AddressOfCallBacks; DWORD SizeOfZeroFill; DWORD Characteristics; };
        BYTE* base = new_image;
        DWORD peoff = *(DWORD*)(base + 0x3C);
        BYTE* nt_headers = base + peoff;
        DWORD* tls_dir_va  = (DWORD*)(nt_headers + 0xD0);
        DWORD* tls_dir_sz  = (DWORD*)(nt_headers + 0xD4);
        DWORD tls_dir_rva = 0;
        for (DWORD i = 0; i < header->num_sections; ++i) {
            const PackedSection& s = header->sections[i];
            if (s.rva <= header->tls_info.start_addr_rva && header->tls_info.start_addr_rva < s.rva + s.virtual_size) {
                tls_dir_rva = (header->tls_info.start_addr_rva + 0x100) & ~0xFF;
                if (tls_dir_rva + sizeof(TlsDirectory) <= s.rva + s.virtual_size) {
                    *tls_dir_va = tls_dir_rva;
                    *tls_dir_sz = sizeof(TlsDirectory);
                    break;
                }
            }
        }
        if (tls_dir_rva > 0) {
            TlsDirectory* tls_dir = (TlsDirectory*)(new_image + tls_dir_rva);
            tls_dir->StartAddressOfRawData = (QWORD)(new_image + header->tls_info.start_addr_rva);
            tls_dir->EndAddressOfRawData = (QWORD)(new_image + header->tls_info.end_addr_rva);
            tls_dir->AddressOfIndex = (QWORD)(new_image + header->tls_info.index_rva);
            tls_dir->AddressOfCallBacks = (QWORD)(new_image + header->tls_info.callback_array_rva);
            tls_dir->SizeOfZeroFill = header->tls_info.zero_fill_size;
            tls_dir->Characteristics = 0;
        }
        if (header->tls_info.num_callbacks > 0) {
            typedef void (NTAPI *TLS_CALLBACK)(LPVOID DllHandle, DWORD Reason, LPVOID Reserved);
            QWORD* callbacks = (QWORD*)(new_image + header->tls_info.callback_array_rva);
			for (DWORD i = 0; i < header->tls_info.num_callbacks; ++i) {
				QWORD va = callbacks[i];
				if (!va) break;
				TLS_CALLBACK cb;
				if (va >= (QWORD)new_image && va < (QWORD)new_image + header->image_size) {
					cb = (TLS_CALLBACK)(va);
				} else {
					cb = (TLS_CALLBACK)(new_image + (va - header->image_base));
				}
				cb((LPVOID)new_image, 1 , 0);
			}
        }
    }
    // Restore resources
	if (header->has_resources) {
        if (pDbg) {
            char msg[128] = "[STUB] Resource dir RVA: ";
            char hex[9];
            DWORD rva = header->resource_dir_rva;
            for (int i = 7; i >= 0; i--) {
                hex[i] = "0123456789ABCDEF"[rva & 0xF];
                rva >>= 4;
            }
            hex[8] = 0;
            my_strcat(msg, hex);
            pDbg(msg);
        }
        BYTE* nt_headers = new_image + *(DWORD*)(new_image + 0x3C);
        DWORD* resource_dir_entry = (DWORD*)(nt_headers + 0x88);
        *resource_dir_entry = header->resource_dir_rva;
        *(resource_dir_entry + 1) = header->resource_dir_size;
        if (pDbg) pDbg("[STUB] Updated resource directory entry");
    }
    // Restore delay imports
    if (header->has_delay_imports && header->delay_import_rva && header->delay_import_size) {
        BYTE* nt_headers = new_image + *(DWORD*)(new_image + 0x3C);
        IMAGE_DATA_DIRECTORY* dirs = (IMAGE_DATA_DIRECTORY*)(nt_headers + 0x88); 
        dirs[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress = header->delay_import_rva;
        dirs[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size = header->delay_import_size;
        if (pDbg) pDbg("[STUB] Restored delay import directory");
    }
    // Restore IAT
    if (header->iat_rva && header->iat_size) {
        BYTE* nt_headers = new_image + *(DWORD*)(new_image + 0x3C);
        IMAGE_DATA_DIRECTORY* dirs = (IMAGE_DATA_DIRECTORY*)(nt_headers + 0x88);
        dirs[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = header->iat_rva;
        dirs[IMAGE_DIRECTORY_ENTRY_IAT].Size = header->iat_size;
        if (pDbg) pDbg("[STUB] Restored IAT directory");
    }
    // Restore exception directory
    if (header->exception_rva && header->exception_size) {
        BYTE* nt_headers = new_image + *(DWORD*)(new_image + 0x3C);
        IMAGE_DATA_DIRECTORY* dirs = (IMAGE_DATA_DIRECTORY*)(nt_headers + 0x88);
        dirs[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress = header->exception_rva;
        dirs[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size = header->exception_size;
        if (pDbg) pDbg("[STUB] Restored Exception directory (.pdata)");
    }
    // Restore debug directory
    if (header->has_debug_dir) {
        BYTE* nt_headers = new_image + *(DWORD*)(new_image + 0x3C);
        IMAGE_DATA_DIRECTORY* dirs = (IMAGE_DATA_DIRECTORY*)(nt_headers + 0x88);
        dirs[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress = header->debug_rva;
        dirs[IMAGE_DIRECTORY_ENTRY_DEBUG].Size = header->debug_size;
        if (pDbg) pDbg("[STUB] Restored Debug directory");
    }
    // Restore authenticode
    if (header->has_security_dir) {
        BYTE* nt_headers = new_image + *(DWORD*)(new_image + 0x3C);
        IMAGE_DATA_DIRECTORY* dirs = (IMAGE_DATA_DIRECTORY*)(nt_headers + 0x88);
        dirs[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress = header->security_offset; 
        dirs[IMAGE_DIRECTORY_ENTRY_SECURITY].Size = header->security_size;
        if (pDbg) pDbg("[STUB] Restored Security directory (Authenticode)");
    }
    // Register exception handlers
    auto nt = (IMAGE_NT_HEADERS64*)(new_image + ((IMAGE_DOS_HEADER*)new_image)->e_lfanew);
    auto& exception_dir = nt->OptionalHeader.DataDirectory[3];
    if (exception_dir.VirtualAddress && exception_dir.Size && pRtlAddFunctionTable) {
        auto rf = (RUNTIME_FUNCTION*)(new_image + exception_dir.VirtualAddress);
        auto count = exception_dir.Size / sizeof(RUNTIME_FUNCTION);
        pRtlAddFunctionTable(rf, count, (QWORD)new_image);
        if (pDbg) pDbg("[STUB] Registered exception handlers");
    }
    // Process load config and security cookie
	if (header->has_load_config) {
		BYTE* nt_headers = new_image + *(DWORD*)(new_image + 0x3C);
		DWORD* load_config_dir_entry = (DWORD*)(nt_headers + 0xA8);
		if (pDbg) {
			char msg[64] = "[STUB] Setting LCD to RVA: ";
			char hex[9];
			DWORD rva = header->load_config_dir_rva;
			for (int i = 7; i >= 0; i--) {
				hex[i] = "0123456789ABCDEF"[rva & 0xF];
				rva >>= 4;
			}
			hex[8] = 0;
			my_strcat(msg, hex);
			pDbg(msg);
		}
		*load_config_dir_entry = header->load_config_dir_rva;
		*(load_config_dir_entry + 1) = header->load_config_dir_size;
		if (pDbg) pDbg("[STUB] Updated load config directory entry");
	}
	if (header->has_load_config) {  
		BYTE* nt_headers = new_image + *(DWORD*)(new_image + 0x3C);
		DWORD* lcd_entry = (DWORD*)(nt_headers + 0xA8);
		DWORD lcd_rva = *lcd_entry;
		DWORD lcd_size = *(lcd_entry + 1);
		if (lcd_rva && lcd_size) {
			if (pDbg) pDbg("[STUB] Processing load config directory");
			if (pDbg) {
				char msg[64] = "[STUB] LCD RVA: ";
				char hex[9];
				DWORD rva = lcd_rva;  
				for (int i = 7; i >= 0; i--) {
					hex[i] = "0123456789ABCDEF"[rva & 0xF];
					rva >>= 4;
				}
				hex[8] = 0;
				my_strcat(msg, hex);
				pDbg(msg);
			}
			bool lcd_valid = false;
			for (DWORD i = 0; i < header->num_sections; ++i) {
				const PackedSection& s = header->sections[i];
				if (lcd_rva >= s.rva && lcd_rva + sizeof(IMAGE_LOAD_CONFIG_DIRECTORY64) <= s.rva + s.virtual_size) {
					lcd_valid = true;
					if (pDbg) pDbg("[STUB] LCD RVA is within valid section");
					break;
				}
			}
			if (!lcd_valid) {
				if (pDbg) pDbg("[STUB] WARNING: LCD RVA is outside valid sections, skipping");
			} else {
				auto lcd = (IMAGE_LOAD_CONFIG_DIRECTORY64*)(new_image + lcd_rva);
				if (pDbg) pDbg("[STUB] Got LCD pointer");
				if (pDbg) pDbg("[STUB] Reading SecurityCookie field");
				{
                    // Get security cookie, yum
					QWORD va = lcd->SecurityCookie;
					if (pDbg) {
						char msg[64] = "[STUB] SecurityCookie VA: ";
						char hex[17];
						QWORD t = va;
						for (int i = 15; i >= 0; --i) { hex[i] = "0123456789ABCDEF"[t & 0xF]; t >>= 4; }
						hex[16] = 0; my_strcat(msg, hex); pDbg(msg);
					}
					if (va) {
						QWORD cookie_addr = 0;
						if (va >= (QWORD)new_image && va < (QWORD)new_image + header->image_size) {
							cookie_addr = va;
						} else {
							QWORD off = va - header->image_base;
							if (off < header->image_size) cookie_addr = (QWORD)(new_image + off);
						}
						if (cookie_addr) {
							QWORD* cookie = (QWORD*)cookie_addr;
							*cookie = __rdtsc() ^ (QWORD)new_image;
							if (pDbg) pDbg("[STUB] Initialized security cookie");
						} else {
							if (pDbg) pDbg("[STUB] WARNING: SecurityCookie not in image range");
						}
					}
				}
                // Setup CFG stubs
				if (pDbg) pDbg("[STUB] Checking CFG check pointer");
				if (lcd->GuardCFCheckFunctionPointer) {
					QWORD addr = lcd->GuardCFCheckFunctionPointer;
					void** slot = 0;
					if (addr >= (QWORD)new_image && addr < (QWORD)new_image + header->image_size) {
						slot = (void**)addr;
					} else {
						QWORD off = addr - header->image_base;
						if (off < header->image_size) slot = (void**)(new_image + off);
					}
					if (slot) {
						*slot = (void*)&cfg_check_icall_stub;
						if (pDbg) pDbg("[STUB] Set CFG check pointer to stub");
					} else {
						if (pDbg) pDbg("[STUB] WARNING: CFG check pointer outside image");
					}
				}
				if (pDbg) pDbg("[STUB] Checking CFG dispatch pointer");
				if (lcd->GuardCFDispatchFunctionPointer) {
					QWORD addr = lcd->GuardCFDispatchFunctionPointer;
					void** slot = 0;
					if (addr >= (QWORD)new_image && addr < (QWORD)new_image + header->image_size) {
						slot = (void**)addr;
					} else {
						QWORD off = addr - header->image_base;
						if (off < header->image_size) slot = (void**)(new_image + off);
					}
					if (slot) {
						*slot = (void*)&cfg_dispatch_icall_stub;
						if (pDbg) pDbg("[STUB] Set CFG dispatch pointer to stub");
					} else {
						if (pDbg) pDbg("[STUB] WARNING: CFG dispatch pointer outside image");
					}
				}
                if (header->seh_table_rva && header->seh_count) {
                    lcd->SEHandlerTable = header->image_base + header->seh_table_rva;
                    lcd->SEHandlerCount = header->seh_count;
                    if (pDbg) pDbg("[STUB] Restored SEH handler table");
                }
				if (pDbg) pDbg("[STUB] Load config processing complete");
			}
		}
	}
    // Fix section protections
    for (DWORD i = 0; i < header->num_sections; ++i) {
		const PackedSection& s = header->sections[i];
		DWORD prot = char_to_protection(s.characteristics);
		if (header->has_imports && 
			header->import_dir_rva >= s.rva && 
			header->import_dir_rva < s.rva + s.virtual_size) {
			if (prot == 0x20) prot = 0x40;  
			else prot = 0x04;               
		}
		DWORD oldProt = 0;
		pVirtualProtect(new_image + s.rva, (SIZE_T)s.virtual_size, prot, &oldProt);
		if (pDbg) {
			char msg[128] = "[STUB] Set section ";
			char hex[9];
			DWORD rva = s.rva;
			for (int k = 7; k >= 0; k--) {
				hex[k] = "0123456789ABCDEF"[rva & 0xF];
				rva >>= 4;
			}
			hex[8] = 0;
			my_strcat(msg, hex);
			my_strcat(msg, " protection to ");
			char prot_hex[9];
			DWORD p = prot;
			for (int k = 7; k >= 0; k--) {
				prot_hex[k] = "0123456789ABCDEF"[p & 0xF];
				p >>= 4;
			}
			prot_hex[8] = 0;
			my_strcat(msg, prot_hex);
			pDbg(msg);
		}
	}
    // Flush and jump
    pFlush(pGetCurrentProcess(), new_image, (SIZE_T)header->image_size);
    if (pDbg) pDbg("[STUB] Flushed instruction cache");
    if (pDbg) {
        char buf[64];
        DWORD oep = header->original_entry_point;
        DWORD val = *(DWORD*)(new_image + oep);
        auto hex32 = [](DWORD v, char* out) {
            const char* hex="0123456789ABCDEF";
            for(int i=0;i<8;i++){ out[7-i]=hex[v&0xF]; v>>=4; }
            out[8]=0;
        };
        char valhex[9]; hex32(val,valhex);
        char oephex[9]; hex32(oep,oephex);
        int pos=0; buf[pos++]='\0';
        pDbg("[STUB] OEP RVA check");
        pDbg(oephex);
        pDbg(valhex);
    }
	if (pDbg) {
		for (DWORD i = 0; i < header->num_sections; ++i) {
			const PackedSection& s = header->sections[i];
			if (header->original_entry_point >= s.rva && 
				header->original_entry_point < s.rva + s.virtual_size) {
				char msg[128];
				DWORD expected_prot = char_to_protection(s.characteristics);
				my_strcpy(msg, "[STUB] OEP section characteristics: 0x");
				char hex[9];
				DWORD val = s.characteristics;
				for (int j = 7; j >= 0; j--) {
					hex[j] = "0123456789ABCDEF"[val & 0xF];
					val >>= 4;
				}
				hex[8] = 0;
				my_strcat(msg, hex);
				my_strcat(msg, " -> prot: 0x");
				val = expected_prot;
				for (int j = 7; j >= 0; j--) {
					hex[j] = "0123456789ABCDEF"[val & 0xF];
					val >>= 4;
				}
				hex[8] = 0;
				my_strcat(msg, hex);
				pDbg(msg);
				break;
			}
		}
	}
    if (pDbg) pDbg("[STUB] *** JUMPING TO ORIGINAL ENTRY POINT ***");
    void (*entry)() = (void(*)())(new_image + header->original_entry_point);
    entry();
#endif
}
// Entry points
extern "C" void stub_main() {
    do_unpack();
}
#ifndef BUILD_STUB_EXE
extern "C" {
    extern const BYTE  stub_bytes[];
    extern const DWORD stub_size;
}
#endif