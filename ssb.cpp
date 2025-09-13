// ssb.cpp
#include <windows.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>
#include <cassert>
#include <iomanip>
#include <algorithm>
#include "stub_bytes.h"
// Stub entry point we'll patch
extern unsigned int stub_entry_rva;
bool g_debug_mode = false;
// Helper templates
template<typename T>
T min_val(T a, T b) {
    return (a < b) ? a : b;
}
template<typename T>
T max_val(T a, T b) {
    return (a > b) ? a : b;
}
#define DEBUG_OUT if (g_debug_mode) std::cout
// Pack it tight
#pragma pack(push, 1)
struct StubTLS {
    uint32_t callbacks_rva;
    uint32_t num_callbacks;
    uint32_t start_addr_rva;
    uint32_t end_addr_rva;
    uint32_t index_rva;
    uint32_t callback_array_rva;
    uint32_t zero_fill_size;
};
struct PackedSection {
    uint32_t rva;
    uint32_t compressed_size;
    uint32_t decompressed_size;
    uint32_t virtual_size;
    uint32_t characteristics;
    uint32_t offset_in_blob;
};
struct StubHeader {
    uint32_t magic;
    uint32_t num_sections;
    uint32_t original_entry_point;
    uint64_t image_base;
    uint64_t image_size;
    uint32_t has_tls;
    StubTLS tls_info;
    uint32_t has_imports;
    uint32_t import_dir_rva;
    uint32_t import_dir_size;
    uint32_t has_relocs;
    uint32_t reloc_dir_rva;
    uint32_t reloc_dir_size;
    uint32_t has_load_config;
    uint32_t load_config_dir_rva;
    uint32_t load_config_dir_size;
    uint32_t has_resources;
    uint32_t resource_dir_rva;
    uint32_t resource_dir_size;
    uint32_t has_delay_imports;
    uint32_t delay_import_rva;
    uint32_t delay_import_size;
    uint32_t seh_table_rva;
    uint32_t seh_count;
    uint32_t iat_rva;
    uint32_t iat_size;
    uint32_t exception_rva;
    uint32_t exception_size;
    uint32_t has_debug_dir;
    uint32_t debug_rva;
    uint32_t debug_size;
    uint32_t has_security_dir;
    uint32_t security_offset;
    uint32_t security_size;
    PackedSection sections[32];
};
#pragma pack(pop)
// PE parsing data
struct PEInfo {
    IMAGE_DOS_HEADER dos;
    IMAGE_NT_HEADERS64 nt;
    std::vector<IMAGE_SECTION_HEADER> secs;
    std::vector<uint8_t> raw;
};
// Pretty progress bar
void print_progress_bar(const std::string& operation, size_t current, size_t total) {
    static int last_percent = -1;
    int current_percent = (int)((double)current / total * 100.0);
    if (current_percent >= 90) {
        current_percent = 100;
    }
    if (current_percent == last_percent) {
        return;
    }
    last_percent = current_percent;
    const int bar_width = 40;
    double progress = (double)current_percent / 100.0;
    int pos = (int)(bar_width * progress);
    std::cout << "\r" << operation << " [";
    for (int i = 0; i < bar_width; ++i) {
        if (i < pos) std::cout << "=";
        else if (i == pos) std::cout << ">";
        else std::cout << " ";
    }
    std::cout << "] " << std::fixed << std::setprecision(1)
              << (progress * 100.0) << "%";
    std::cout.flush();
}
// LZSS compressor, make it small
std::vector<uint8_t> lzss_compress(const uint8_t* data,
                                   size_t size,
                                   size_t section_idx = 0,
                                   size_t total_sections = 0)
{
    const size_t WINDOW_SIZE = 4096;
    const size_t MAX_MATCH   = 18;
    const size_t MIN_MATCH   = 3;
    std::vector<uint8_t> compressed;
    compressed.reserve(size / 2);
    size_t pos = 0;
    while (pos < size) {
        uint8_t flags = 0;
        std::vector<uint8_t> chunk;
        chunk.reserve(16);
        for (int bit = 0; bit < 8 && pos < size; bit++) {
            size_t best_len  = 0;
            size_t best_dist = 0;
            size_t window_start = (pos >= WINDOW_SIZE) ? pos - WINDOW_SIZE : 0;
            for (size_t i = pos; i-- > window_start;) {
                if (data[i] != data[pos]) continue;
                size_t len = 1;
                while (len + 8 <= MAX_MATCH &&
                       pos + len + 8 <= size) {
                    uint64_t a = *reinterpret_cast<const uint64_t*>(&data[i + len]);
                    uint64_t b = *reinterpret_cast<const uint64_t*>(&data[pos + len]);
                    if (a != b) break;
                    len += 8;
                }
                while (len < MAX_MATCH &&
                       pos + len < size &&
                       data[i + len] == data[pos + len]) {
                    len++;
                }
                if (len > best_len) {
                    best_len  = len;
                    best_dist = pos - i;
                    if (len == MAX_MATCH) break;
                }
            }
            if (best_len >= MIN_MATCH) {
                uint16_t match = ((best_len - MIN_MATCH) << 12) |
                                 ((best_dist - 1) & 0xFFF);
                chunk.push_back(static_cast<uint8_t>(match >> 8));
                chunk.push_back(static_cast<uint8_t>(match & 0xFF));
                pos += best_len;
            } else {
                flags |= (1 << bit);
                chunk.push_back(data[pos++]);
            }
        }
        compressed.push_back(flags);
        compressed.insert(compressed.end(), chunk.begin(), chunk.end());
        if (total_sections > 0 && !g_debug_mode) {
            size_t overall_progress = section_idx * 100 + (pos * 100) / size;
            size_t overall_total    = total_sections * 100;
            print_progress_bar("Compressing", overall_progress, overall_total);
        }
    }
    return compressed;
}
// Parse that PE
PEInfo parse_pe(const std::string& path) {
    PEInfo pe{};
    std::ifstream f(path, std::ios::binary);
    f.seekg(0, std::ios::end);
    size_t sz = f.tellg();
    f.seekg(0, std::ios::beg);
    pe.raw.resize(sz);
    f.read((char*)pe.raw.data(), sz);
    f.close();
    pe.dos = *(IMAGE_DOS_HEADER*)pe.raw.data();
    pe.nt = *(IMAGE_NT_HEADERS64*)(pe.raw.data() + pe.dos.e_lfanew);
    auto* shdr = (IMAGE_SECTION_HEADER*)(pe.raw.data() + pe.dos.e_lfanew +
                 sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER) + pe.nt.FileHeader.SizeOfOptionalHeader);
    for (int i = 0; i < pe.nt.FileHeader.NumberOfSections; i++) pe.secs.push_back(shdr[i]);
    return pe;
}
// RVA to file offset converter
static DWORD rva_to_file_offset(const PEInfo& pe, DWORD rva) {
    for (const auto& s : pe.secs) {
        DWORD va = s.VirtualAddress;
        DWORD vsz = s.Misc.VirtualSize;
        DWORD rsz = s.SizeOfRawData;
        if (rva >= va && rva < va + vsz) {
            DWORD delta = rva - va;
            if (delta > rsz) { 
                return s.PointerToRawData + rsz;
            }
            return s.PointerToRawData + delta;
        }
    }
    return 0;
}
// Extract manifest from resources
static bool extract_manifest_blob(const PEInfo& pe,
                                  std::vector<uint8_t>& manifest,
                                  DWORD& out_lang) {
    auto& dd = pe.nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
    if (!dd.VirtualAddress || !dd.Size) return false;
    DWORD rsrc_file_off = rva_to_file_offset(pe, dd.VirtualAddress);
    if (!rsrc_file_off || rsrc_file_off >= pe.raw.size()) return false;
    const BYTE* base = pe.raw.data() + rsrc_file_off;
    const DWORD rsrc_rva = dd.VirtualAddress;
    auto root = (const IMAGE_RESOURCE_DIRECTORY*)base;
    auto entries = (const IMAGE_RESOURCE_DIRECTORY_ENTRY*)(base + sizeof(IMAGE_RESOURCE_DIRECTORY));
    int n = root->NumberOfNamedEntries + root->NumberOfIdEntries;
    auto dir_at = [&](DWORD off) -> const IMAGE_RESOURCE_DIRECTORY* {
        return (const IMAGE_RESOURCE_DIRECTORY*)(base + (off & 0x7FFFFFFF));
    };
    auto entries_at = [&](DWORD off) -> const IMAGE_RESOURCE_DIRECTORY_ENTRY* {
        const BYTE* p = base + (off & 0x7FFFFFFF);
        return (const IMAGE_RESOURCE_DIRECTORY_ENTRY*)(p + sizeof(IMAGE_RESOURCE_DIRECTORY));
    };
    int type_idx = -1;
    for (int i = 0; i < n; ++i) {
        DWORD id = entries[i].Name;               
        bool is_dir = (entries[i].OffsetToData & 0x80000000u) != 0;
        if (!is_dir) continue;
        if ((id & 0x80000000u) == 0 && (id & 0xFFFFu) == 24) { type_idx = i; break; }
    }
    if (type_idx < 0) return false;
    auto type_dir_off = entries[type_idx].OffsetToData;
    auto type_dir = dir_at(type_dir_off);
    auto type_entries = entries_at(type_dir_off);
    int tcount = type_dir->NumberOfNamedEntries + type_dir->NumberOfIdEntries;
    int name_idx = -1;
    for (int i = 0; i < tcount; ++i) {
        DWORD id = type_entries[i].Name;
        bool is_dir = (type_entries[i].OffsetToData & 0x80000000u) != 0;
        if (!is_dir) continue;
        if ((id & 0x80000000u) == 0 && (id & 0xFFFFu) == 1) { name_idx = i; break; }
    }
    if (name_idx < 0 && tcount > 0) name_idx = 0; 
    auto name_dir_off = type_entries[name_idx].OffsetToData;
    auto name_dir = dir_at(name_dir_off);
    auto lang_entries = entries_at(name_dir_off);
    int lcount = name_dir->NumberOfNamedEntries + name_dir->NumberOfIdEntries;
    if (lcount <= 0) return false;
    DWORD lang_id = lang_entries[0].Name & 0xFFFFu;
    bool is_data = (lang_entries[0].OffsetToData & 0x80000000u) == 0;
    if (!is_data) return false;
    auto data_entry = (const IMAGE_RESOURCE_DATA_ENTRY*)(base + (lang_entries[0].OffsetToData & 0x7FFFFFFFu));
    DWORD data_rva  = data_entry->OffsetToData;
    DWORD data_size = data_entry->Size;
    DWORD data_off = rva_to_file_offset(pe, data_rva);
    if (!data_off || data_off + data_size > pe.raw.size()) return false;
    manifest.assign(pe.raw.begin() + data_off, pe.raw.begin() + data_off + data_size);
    out_lang = lang_id ? lang_id : 0x409; 
    return true;
}
// Build resource section for manifest
static std::vector<uint8_t> build_manifest_rsrc_blob(const std::vector<uint8_t>& manifest,
                                                     DWORD lang_id,
                                                     DWORD rsrc_va) {
    const size_t root_dir_ofs = 0;
    const size_t root_size = sizeof(IMAGE_RESOURCE_DIRECTORY);
    const size_t root_entries_size = sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY); 
    const size_t type_dir_ofs = root_dir_ofs + root_size + root_entries_size;
    const size_t type_size = sizeof(IMAGE_RESOURCE_DIRECTORY);
    const size_t type_entries_size = sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY); 
    const size_t name_dir_ofs = type_dir_ofs + type_size + type_entries_size;
    const size_t name_size = sizeof(IMAGE_RESOURCE_DIRECTORY);
    const size_t name_entries_size = sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY); 
    const size_t data_entry_ofs = name_dir_ofs + name_size + name_entries_size;
    size_t data_blob_ofs = (data_entry_ofs + sizeof(IMAGE_RESOURCE_DATA_ENTRY) + 3) & ~size_t(3);
    size_t total = data_blob_ofs + manifest.size();
    std::vector<uint8_t> blob(total, 0);
    auto* root = (IMAGE_RESOURCE_DIRECTORY*)&blob[root_dir_ofs];
    auto* root_ent = (IMAGE_RESOURCE_DIRECTORY_ENTRY*)&blob[root_dir_ofs + root_size];
    auto* type_dir = (IMAGE_RESOURCE_DIRECTORY*)&blob[type_dir_ofs];
    auto* type_ent = (IMAGE_RESOURCE_DIRECTORY_ENTRY*)&blob[type_dir_ofs + type_size];
    auto* name_dir = (IMAGE_RESOURCE_DIRECTORY*)&blob[name_dir_ofs];
    auto* name_ent = (IMAGE_RESOURCE_DIRECTORY_ENTRY*)&blob[name_dir_ofs + name_size];
    auto* data_ent = (IMAGE_RESOURCE_DATA_ENTRY*)&blob[data_entry_ofs];
    root->NumberOfNamedEntries = 0;
    root->NumberOfIdEntries    = 1;
    root_ent->Name = 24; 
    root_ent->OffsetToData = 0x80000000u | (DWORD)type_dir_ofs;
    type_dir->NumberOfNamedEntries = 0;
    type_dir->NumberOfIdEntries    = 1;
    type_ent->Name = 1; 
    type_ent->OffsetToData = 0x80000000u | (DWORD)name_dir_ofs;
    name_dir->NumberOfNamedEntries = 0;
    name_dir->NumberOfIdEntries    = 1;
    name_ent->Name = lang_id; 
    name_ent->OffsetToData = (DWORD)data_entry_ofs; 
    data_ent->OffsetToData = rsrc_va + (DWORD)data_blob_ofs; 
    data_ent->Size = (DWORD)manifest.size();
    data_ent->CodePage = 0;
    data_ent->Reserved = 0;
    memcpy(&blob[data_blob_ofs], manifest.data(), manifest.size());
    return blob;
}
// Main packing function - where the magic happens
std::vector<uint8_t> build_ssb_packed(PEInfo& pe) {
    const DWORD sectAlign = 0x1000;
    const DWORD fileAlign = 0x200;
    StubHeader sh{};
    sh.magic = 0x58505553;
    sh.original_entry_point = pe.nt.OptionalHeader.AddressOfEntryPoint;
    sh.image_base = pe.nt.OptionalHeader.ImageBase;
    sh.image_size = pe.nt.OptionalHeader.SizeOfImage;
    sh.num_sections = 0;
    sh.has_tls = 0;
    sh.has_imports = 0;
    sh.has_relocs = 0;
    sh.has_load_config = 0;
    sh.has_resources = 0;
    sh.has_delay_imports = 0;
    sh.delay_import_rva = 0;
    sh.delay_import_size = 0;
    sh.seh_table_rva = 0;
    sh.seh_count = 0;
    DEBUG_OUT << "=== ANALYZING PE STRUCTURE ===" << std::endl;
    DEBUG_OUT << "Original entry point: 0x" << std::hex << sh.original_entry_point << std::dec << std::endl;
    DEBUG_OUT << "Image base: 0x" << std::hex << sh.image_base << std::dec << std::endl;
    DEBUG_OUT << "Image size: 0x" << std::hex << sh.image_size << std::dec << std::endl;
    // Check for TLS
    auto& tls_dir = pe.nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (tls_dir.Size > 0 && tls_dir.VirtualAddress > 0) {
        for (const auto& s : pe.secs) {
            if (tls_dir.VirtualAddress >= s.VirtualAddress && 
                tls_dir.VirtualAddress < s.VirtualAddress + s.Misc.VirtualSize) {
                uint32_t offset_in_section = tls_dir.VirtualAddress - s.VirtualAddress;
                uint32_t file_offset = s.PointerToRawData + offset_in_section;
                if (file_offset + sizeof(IMAGE_TLS_DIRECTORY64) <= pe.raw.size()) {
                    auto* tls_data = (IMAGE_TLS_DIRECTORY64*)(pe.raw.data() + file_offset);
                    sh.has_tls = 1;
                    sh.tls_info.start_addr_rva = static_cast<uint32_t>(tls_data->StartAddressOfRawData - pe.nt.OptionalHeader.ImageBase);
                    sh.tls_info.end_addr_rva = static_cast<uint32_t>(tls_data->EndAddressOfRawData - pe.nt.OptionalHeader.ImageBase);
                    sh.tls_info.index_rva = static_cast<uint32_t>(tls_data->AddressOfIndex - pe.nt.OptionalHeader.ImageBase);
                    sh.tls_info.callback_array_rva = static_cast<uint32_t>(tls_data->AddressOfCallBacks - pe.nt.OptionalHeader.ImageBase);
                    sh.tls_info.zero_fill_size = tls_data->SizeOfZeroFill;
                    sh.tls_info.num_callbacks = 0;
                    if (sh.tls_info.callback_array_rva > 0) {
                        for (const auto& cb_sec : pe.secs) {
                            uint32_t cb_rva = sh.tls_info.callback_array_rva;
                            if (cb_rva >= cb_sec.VirtualAddress && 
                                cb_rva < cb_sec.VirtualAddress + cb_sec.Misc.VirtualSize) {
                                uint32_t cb_offset = cb_rva - cb_sec.VirtualAddress + cb_sec.PointerToRawData;
                                auto* callbacks = (uint64_t*)(pe.raw.data() + cb_offset);
                                while (cb_offset + sh.tls_info.num_callbacks * 8 < pe.raw.size() && 
                                       callbacks[sh.tls_info.num_callbacks] != 0) {
                                    sh.tls_info.num_callbacks++;
                                }
                                break;
                            }
                        }
                    }
                    DEBUG_OUT << "TLS directory found with " << sh.tls_info.num_callbacks << " callbacks" << std::endl;
                }
                break;
            }
        }
    }
    // Check all the directories
    auto& load_config_dir = pe.nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
    if (load_config_dir.Size > 0 && load_config_dir.VirtualAddress > 0) {
        sh.has_load_config = 1;
        sh.load_config_dir_rva = load_config_dir.VirtualAddress;
        sh.load_config_dir_size = load_config_dir.Size;
        DEBUG_OUT << "Load config directory found at RVA 0x" << std::hex << load_config_dir.VirtualAddress << std::dec << std::endl;
        if (load_config_dir.Size >= sizeof(IMAGE_LOAD_CONFIG_DIRECTORY64)) {
            DWORD lcd_off = rva_to_file_offset(pe, load_config_dir.VirtualAddress);
            if (lcd_off && lcd_off + sizeof(IMAGE_LOAD_CONFIG_DIRECTORY64) <= pe.raw.size()) {
                auto lcd = (const IMAGE_LOAD_CONFIG_DIRECTORY64*)(pe.raw.data() + lcd_off);
                if (lcd->SEHandlerTable && lcd->SEHandlerCount) {
                    sh.seh_table_rva = static_cast<uint32_t>(lcd->SEHandlerTable - pe.nt.OptionalHeader.ImageBase);
                    sh.seh_count = static_cast<uint32_t>(lcd->SEHandlerCount);
                    DEBUG_OUT << "SEH handler table found: " << sh.seh_count << " handlers at RVA 0x" 
                              << std::hex << sh.seh_table_rva << std::dec << std::endl;
                }
            }
        }
    }
    auto& import_dir = pe.nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (import_dir.Size > 0 && import_dir.VirtualAddress > 0) {
        sh.has_imports = 1;
        sh.import_dir_rva = import_dir.VirtualAddress;
        sh.import_dir_size = import_dir.Size;
        DEBUG_OUT << "Import directory: RVA 0x" << std::hex << import_dir.VirtualAddress 
                  << std::dec << ", size " << import_dir.Size << std::endl;
    }
    auto& reloc_dir = pe.nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (reloc_dir.Size > 0 && reloc_dir.VirtualAddress > 0) {
        sh.has_relocs = 1;
        sh.reloc_dir_rva = reloc_dir.VirtualAddress;
        sh.reloc_dir_size = reloc_dir.Size;
        DEBUG_OUT << "Relocation directory: RVA 0x" << std::hex << reloc_dir.VirtualAddress 
                  << std::dec << ", size " << reloc_dir.Size << std::endl;
    }
	auto& resource_dir = pe.nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
	if (resource_dir.Size > 0 && resource_dir.VirtualAddress > 0) {
		sh.has_resources = 1;
		sh.resource_dir_rva = resource_dir.VirtualAddress;
		sh.resource_dir_size = resource_dir.Size;
		DEBUG_OUT << "Resource directory: RVA 0x" << std::hex << resource_dir.VirtualAddress 
				<< std::dec << ", size " << resource_dir.Size << std::endl;
	}
    auto& delay_import_dir = pe.nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
    if (delay_import_dir.Size > 0 && delay_import_dir.VirtualAddress > 0) {
        sh.has_delay_imports = 1;
        sh.delay_import_rva = delay_import_dir.VirtualAddress;
        sh.delay_import_size = delay_import_dir.Size;
        DEBUG_OUT << "Delay import directory: RVA 0x" << std::hex << delay_import_dir.VirtualAddress 
                  << std::dec << ", size " << delay_import_dir.Size << std::endl;
    }
    auto& iat_dir = pe.nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];
    if (iat_dir.Size > 0 && iat_dir.VirtualAddress > 0) {
        sh.iat_rva = iat_dir.VirtualAddress;
        sh.iat_size = iat_dir.Size;
        DEBUG_OUT << "IAT directory: RVA 0x" << std::hex << iat_dir.VirtualAddress 
                  << std::dec << ", size " << iat_dir.Size << std::endl;
    }
    auto& exception_dir = pe.nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (exception_dir.Size > 0 && exception_dir.VirtualAddress > 0) {
        sh.exception_rva = exception_dir.VirtualAddress;
        sh.exception_size = exception_dir.Size;
        DEBUG_OUT << "Exception directory (.pdata): RVA 0x" << std::hex << exception_dir.VirtualAddress 
                  << std::dec << ", size " << exception_dir.Size << std::endl;
    }
    auto& debug_dir = pe.nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
    if (debug_dir.Size > 0 && debug_dir.VirtualAddress > 0) {
        sh.has_debug_dir = 1;
        sh.debug_rva = debug_dir.VirtualAddress;
        sh.debug_size = debug_dir.Size;
        DEBUG_OUT << "Debug directory: RVA 0x" << std::hex << debug_dir.VirtualAddress
                  << std::dec << ", size " << debug_dir.Size << std::endl;
    }
    auto& sec_dir = pe.nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
    if (sec_dir.Size > 0 && sec_dir.VirtualAddress > 0) {
        sh.has_security_dir = 1;
        sh.security_offset = sec_dir.VirtualAddress; 
        sh.security_size   = sec_dir.Size;
        DEBUG_OUT << "Security directory (Authenticode): FileOffset 0x" << std::hex << sec_dir.VirtualAddress
                  << std::dec << ", size " << sec_dir.Size << std::endl;
    }
    // Compress it all
    size_t total_sections = pe.secs.size() + 1;
    if (!g_debug_mode) {
        std::cout << "                          Save Some Bytes (SSB)" << std::endl;
        std::cout << "                       Copyright (C) 2025 0xROOTPLS" << std::endl;
        std::cout << "                         Advanced PE Compression" << std::endl;
        std::cout << std::endl;
    }
    DEBUG_OUT << "\n=== COMPRESSION PHASE ===" << std::endl;
    std::vector<uint8_t> blob;
    blob.reserve(1 << 20);
    const DWORD e_lfanew = pe.dos.e_lfanew;
    const DWORD nt_size = sizeof(IMAGE_NT_HEADERS64);
    const DWORD sec_tbl = pe.nt.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
    const DWORD headers_end = e_lfanew + nt_size + sec_tbl;
    PackedSection headers_ps{};
    headers_ps.rva = 0;
    headers_ps.decompressed_size = headers_end;
    headers_ps.virtual_size = headers_end;
    headers_ps.characteristics = IMAGE_SCN_MEM_READ;
    headers_ps.offset_in_blob = static_cast<uint32_t>(blob.size());
    auto hdr_comp = lzss_compress(pe.raw.data(), headers_end, 0, total_sections);
    headers_ps.compressed_size = static_cast<uint32_t>(hdr_comp.size());
    blob.insert(blob.end(), hdr_comp.begin(), hdr_comp.end());
    if (sh.num_sections >= 32) throw std::runtime_error("Too many sections");
    sh.sections[sh.num_sections++] = headers_ps;
    DEBUG_OUT << "Headers: " << headers_end << " -> " << hdr_comp.size() << " bytes ("
              << std::fixed << std::setprecision(1) << (double)hdr_comp.size() / headers_end * 100 << "%)" << std::endl;
    size_t current_section = 1;
    for (const auto& s : pe.secs) {
        if (s.SizeOfRawData == 0) continue;
        char name[9] = {0}; 
        memcpy(name, s.Name, 8);
        DWORD size_to_compress = s.SizeOfRawData;
        if (s.PointerToRawData + size_to_compress > pe.raw.size()) {
            size_to_compress = pe.raw.size() - s.PointerToRawData;
        }
        const uint8_t* src = pe.raw.data() + s.PointerToRawData;
        auto comp = lzss_compress(src, size_to_compress, current_section, total_sections);
        PackedSection ps{};
        ps.rva = s.VirtualAddress;
        ps.compressed_size = static_cast<uint32_t>(comp.size());
        ps.decompressed_size = size_to_compress;
        ps.virtual_size = s.Misc.VirtualSize;
        ps.characteristics = s.Characteristics;
        ps.offset_in_blob = static_cast<uint32_t>(blob.size());
        if (sh.num_sections >= 32) throw std::runtime_error("Too many sections");
        sh.sections[sh.num_sections++] = ps;
        blob.insert(blob.end(), comp.begin(), comp.end());
        DEBUG_OUT << "Section " << name << ": " << size_to_compress << " -> " << comp.size() 
                  << " bytes (" << std::fixed << std::setprecision(1) 
                  << (double)comp.size() / size_to_compress * 100 << "%)"
                  << " [VirtSize=" << s.Misc.VirtualSize << ", RawSize=" << s.SizeOfRawData << "]" << std::endl;
        current_section++;
    }
    if (!g_debug_mode) {
        std::cout << "\n";
    }
    // Extract manifest if we have one
    std::vector<uint8_t> manifest_blob;
    DWORD manifest_lang = 0x409;
    bool have_manifest = extract_manifest_blob(pe, manifest_blob, manifest_lang);
    DEBUG_OUT << "\n=== BUILDING PACKED PE ===" << std::endl;
    if (have_manifest) {
        DEBUG_OUT << "Found manifest (" << manifest_blob.size() << " bytes), will create .rsrc section" << std::endl;
    }
    // Calculate sizes
    const uint32_t stub_code_size  = static_cast<uint32_t>(stub_size);
    const uint32_t header_size     = static_cast<uint32_t>(sizeof(StubHeader));
    const uint32_t payload_size    = static_cast<uint32_t>(blob.size());
    const uint32_t ssb1_raw         = stub_code_size + header_size + payload_size;
    const uint32_t ssb1_raw_aligned = (ssb1_raw + fileAlign - 1) & ~(fileAlign - 1);
    const uint32_t ssb1_start = 0x1000;
    const uint32_t ssb1_end   = ssb1_start + ((ssb1_raw + sectAlign - 1) & ~(sectAlign - 1));
    const uint32_t header_rva = ssb1_start + stub_code_size;
    DEBUG_OUT << "Stub: " << stub_code_size << " bytes, Header: " << header_size 
              << " bytes, Payload: " << payload_size << " bytes" << std::endl;
    DEBUG_OUT << "Entry point: 0x" << std::hex << (ssb1_start + stub_entry_rva) << std::dec << std::endl;
    // Build PE with manifest
    if (have_manifest) {
        const uint32_t rsrc_start = ssb1_end;
        std::vector<uint8_t> rsrc_blob = build_manifest_rsrc_blob(manifest_blob, manifest_lang, rsrc_start);
        const uint32_t rsrc_raw_aligned = ((uint32_t)rsrc_blob.size() + fileAlign - 1) & ~(fileAlign - 1);
        const uint32_t rsrc_end = rsrc_start + (((uint32_t)rsrc_blob.size() + sectAlign - 1) & ~(sectAlign - 1));
        const uint32_t ssb0_start = rsrc_end;
        const uint32_t ssb0_end   = ssb0_start + ((static_cast<uint32_t>(sh.image_size) + sectAlign - 1) & ~(sectAlign - 1));
        const uint32_t computed_image_size = ssb0_end;
        const DWORD sizeOfHeaders = (sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS64) + 
                                     3 * sizeof(IMAGE_SECTION_HEADER) + fileAlign - 1) & ~(fileAlign - 1);
        std::vector<uint8_t> out(sizeOfHeaders, 0);
        IMAGE_DOS_HEADER dos = pe.dos;
        dos.e_lfanew = 0x80;
        memcpy(out.data(), &dos, sizeof(dos));
        IMAGE_NT_HEADERS64 nt{};
        nt.Signature = IMAGE_NT_SIGNATURE;
        nt.FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
        nt.FileHeader.NumberOfSections = 3;
        nt.FileHeader.TimeDateStamp = pe.nt.FileHeader.TimeDateStamp;
        nt.FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
        nt.FileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE;
        nt.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
        nt.OptionalHeader.MajorLinkerVersion = 14;
        nt.OptionalHeader.MinorLinkerVersion = 0;
        nt.OptionalHeader.SizeOfCode = ssb1_raw_aligned;
        nt.OptionalHeader.SizeOfInitializedData = rsrc_raw_aligned;
        nt.OptionalHeader.SizeOfUninitializedData = 0;
        nt.OptionalHeader.AddressOfEntryPoint = ssb1_start + stub_entry_rva;
        nt.OptionalHeader.BaseOfCode = ssb1_start;
        nt.OptionalHeader.ImageBase = sh.image_base;
        nt.OptionalHeader.SectionAlignment = sectAlign;
        nt.OptionalHeader.FileAlignment = fileAlign;
        nt.OptionalHeader.MajorOperatingSystemVersion = 6;
        nt.OptionalHeader.MinorOperatingSystemVersion = 0;
        nt.OptionalHeader.MajorImageVersion = 0;
        nt.OptionalHeader.MinorImageVersion = 0;
        nt.OptionalHeader.MajorSubsystemVersion = 6;
        nt.OptionalHeader.MinorSubsystemVersion = 0;
        nt.OptionalHeader.SizeOfImage = computed_image_size;
        nt.OptionalHeader.SizeOfHeaders = sizeOfHeaders;
        nt.OptionalHeader.Subsystem = pe.nt.OptionalHeader.Subsystem;
        nt.OptionalHeader.DllCharacteristics = pe.nt.OptionalHeader.DllCharacteristics;
        nt.OptionalHeader.SizeOfStackReserve = pe.nt.OptionalHeader.SizeOfStackReserve;
        nt.OptionalHeader.SizeOfStackCommit = pe.nt.OptionalHeader.SizeOfStackCommit;
        nt.OptionalHeader.SizeOfHeapReserve = pe.nt.OptionalHeader.SizeOfHeapReserve;
        nt.OptionalHeader.SizeOfHeapCommit = pe.nt.OptionalHeader.SizeOfHeapCommit;
        nt.OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
        for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; ++i) {
            nt.OptionalHeader.DataDirectory[i].VirtualAddress = 0;
            nt.OptionalHeader.DataDirectory[i].Size = 0;
        }
        nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress = rsrc_start;
        nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size = (DWORD)rsrc_blob.size();
        memcpy(out.data() + dos.e_lfanew, &nt, sizeof(nt));
        IMAGE_SECTION_HEADER sections[3] = {};
        strcpy((char*)sections[0].Name, ".ssb1");
        sections[0].Misc.VirtualSize = ssb1_raw;
        sections[0].VirtualAddress = ssb1_start;
        sections[0].SizeOfRawData = ssb1_raw_aligned;
        sections[0].PointerToRawData = sizeOfHeaders;
        sections[0].Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
        strcpy((char*)sections[1].Name, ".rsrc");
        sections[1].Misc.VirtualSize = (DWORD)rsrc_blob.size();
        sections[1].VirtualAddress = rsrc_start;
        sections[1].SizeOfRawData = rsrc_raw_aligned;
        sections[1].PointerToRawData = sizeOfHeaders + ssb1_raw_aligned;
        sections[1].Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;
        strcpy((char*)sections[2].Name, ".ssb0");
        sections[2].Misc.VirtualSize = static_cast<uint32_t>(sh.image_size);
        sections[2].VirtualAddress = ssb0_start;
        sections[2].SizeOfRawData = 0;
        sections[2].PointerToRawData = 0;
        sections[2].Characteristics = IMAGE_SCN_CNT_UNINITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
        DWORD sections_offset = dos.e_lfanew + sizeof(nt);
        memcpy(out.data() + sections_offset, sections, sizeof(sections));
        out.resize(sizeOfHeaders + ssb1_raw_aligned + rsrc_raw_aligned, 0);
        uint8_t* ssb1_data = out.data() + sizeOfHeaders;
        std::vector<uint8_t> stub_copy(stub_bytes, stub_bytes + stub_code_size);
        bool patched = false;
        for (size_t i = 0; i <= stub_copy.size() - 4; ++i) {
            uint32_t* p = reinterpret_cast<uint32_t*>(&stub_copy[i]);
            if (*p == 0xDEADBEEF) {
                *p = header_rva;
                DEBUG_OUT << "Patched stub with header RVA: 0x" << std::hex << header_rva << std::dec << std::endl;
                patched = true;
            }
        }
        if (!patched) {
            DEBUG_OUT << "WARNING: header_rva_placeholder not found in stub" << std::endl;
        }
        memcpy(ssb1_data, stub_copy.data(), stub_code_size);
        ssb1_data += stub_code_size;
        memcpy(ssb1_data, &sh, header_size);
        ssb1_data += header_size;
        if (!blob.empty()) memcpy(ssb1_data, blob.data(), payload_size);
        uint8_t* rsrc_data = out.data() + sections[1].PointerToRawData;
        memcpy(rsrc_data, rsrc_blob.data(), rsrc_blob.size());
        return out;
    } else {
        // Build PE without manifest
        const uint32_t ssb0_start = ssb1_end;
        const uint32_t ssb0_end   = ssb0_start + ((static_cast<uint32_t>(sh.image_size) + sectAlign - 1) & ~(sectAlign - 1));
        const uint32_t computed_image_size = ssb0_end;
        const DWORD sizeOfHeaders = (headers_end + fileAlign - 1) & ~(fileAlign - 1);
        std::vector<uint8_t> out(sizeOfHeaders, 0);
        IMAGE_DOS_HEADER dos = pe.dos;
        dos.e_lfanew = 0x80;
        memcpy(out.data(), &dos, sizeof(dos));
        IMAGE_NT_HEADERS64 nt{};
        nt.Signature = IMAGE_NT_SIGNATURE;
        nt.FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
        nt.FileHeader.NumberOfSections = 2;
        nt.FileHeader.TimeDateStamp = pe.nt.FileHeader.TimeDateStamp;
        nt.FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
        nt.FileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE;
        nt.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
        nt.OptionalHeader.MajorLinkerVersion = 14;
        nt.OptionalHeader.MinorLinkerVersion = 0;
        nt.OptionalHeader.SizeOfCode = ssb1_raw_aligned;
        nt.OptionalHeader.SizeOfInitializedData = 0;
        nt.OptionalHeader.SizeOfUninitializedData = 0;
        nt.OptionalHeader.AddressOfEntryPoint = ssb1_start + stub_entry_rva;
        nt.OptionalHeader.BaseOfCode = ssb1_start;
        nt.OptionalHeader.ImageBase = sh.image_base;
        nt.OptionalHeader.SectionAlignment = sectAlign;
        nt.OptionalHeader.FileAlignment = fileAlign;
        nt.OptionalHeader.MajorOperatingSystemVersion = 6;
        nt.OptionalHeader.MinorOperatingSystemVersion = 0;
        nt.OptionalHeader.MajorImageVersion = 0;
        nt.OptionalHeader.MinorImageVersion = 0;
        nt.OptionalHeader.MajorSubsystemVersion = 6;
        nt.OptionalHeader.MinorSubsystemVersion = 0;
        nt.OptionalHeader.SizeOfImage = computed_image_size;
        nt.OptionalHeader.SizeOfHeaders = sizeOfHeaders;
        nt.OptionalHeader.Subsystem = pe.nt.OptionalHeader.Subsystem;
        nt.OptionalHeader.DllCharacteristics = pe.nt.OptionalHeader.DllCharacteristics;
        nt.OptionalHeader.SizeOfStackReserve = pe.nt.OptionalHeader.SizeOfStackReserve;
        nt.OptionalHeader.SizeOfStackCommit = pe.nt.OptionalHeader.SizeOfStackCommit;
        nt.OptionalHeader.SizeOfHeapReserve = pe.nt.OptionalHeader.SizeOfHeapReserve;
        nt.OptionalHeader.SizeOfHeapCommit = pe.nt.OptionalHeader.SizeOfHeapCommit;
        nt.OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
        for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; ++i) {
            nt.OptionalHeader.DataDirectory[i].VirtualAddress = 0;
            nt.OptionalHeader.DataDirectory[i].Size = 0;
        }
        memcpy(out.data() + dos.e_lfanew, &nt, sizeof(nt));
        IMAGE_SECTION_HEADER sections[2] = {};
        strcpy((char*)sections[0].Name, ".ssb1");
        sections[0].Misc.VirtualSize = ssb1_raw;
        sections[0].VirtualAddress = ssb1_start;
        sections[0].SizeOfRawData = ssb1_raw_aligned;
        sections[0].PointerToRawData = sizeOfHeaders;
        sections[0].Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
        strcpy((char*)sections[1].Name, ".ssb0");
        sections[1].Misc.VirtualSize = static_cast<uint32_t>(sh.image_size);
        sections[1].VirtualAddress = ssb0_start;
        sections[1].SizeOfRawData = 0;
        sections[1].PointerToRawData = 0;
        sections[1].Characteristics = IMAGE_SCN_CNT_UNINITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
        DWORD sections_offset = dos.e_lfanew + sizeof(nt);
        memcpy(out.data() + sections_offset, sections, sizeof(sections));
        out.resize(sizeOfHeaders + ssb1_raw_aligned, 0);
        uint8_t* ssb1_data = out.data() + sizeOfHeaders;
        std::vector<uint8_t> stub_copy(stub_bytes, stub_bytes + stub_code_size);
        // Patch the placeholder
        bool patched = false;
        for (size_t i = 0; i <= stub_copy.size() - 4; ++i) {
            uint32_t* p = reinterpret_cast<uint32_t*>(&stub_copy[i]);
            if (*p == 0xDEADBEEF) {
                *p = header_rva;
                DEBUG_OUT << "Patched stub with header RVA: 0x" << std::hex << header_rva << std::dec << std::endl;
                patched = true;
            }
        }
        if (!patched) {
            DEBUG_OUT << "WARNING: header_rva_placeholder not found in stub" << std::endl;
        }
        memcpy(ssb1_data, stub_copy.data(), stub_code_size);
        ssb1_data += stub_code_size;
        memcpy(ssb1_data, &sh, header_size);
        ssb1_data += header_size;
        if (!blob.empty()) memcpy(ssb1_data, blob.data(), payload_size);
        return out;
    }
}
// Usage and main
void show_usage() {
    std::cout << "Save Some Bytes (SSB) Compressor v1.0" << std::endl;
    std::cout << "Copyright (C) 2025 0xROOTPLS" << std::endl;
    std::cout << std::endl;
    std::cout << "Usage: ssb_compressor [options] <input.exe>" << std::endl;
    std::cout << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  --debug    Show detailed debug output" << std::endl;
    std::cout << "  --help     Show this help message" << std::endl;
    std::cout << std::endl;
}
int main(int argc, char* argv[]) {
    std::string input_file;
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--debug") {
            g_debug_mode = true;
        } else if (arg == "--help" || arg == "-h") {
            show_usage();
            return 0;
        } else if (arg.empty() || arg[0] == '-') {
            std::cerr << "Unknown option: " << arg << std::endl;
            show_usage();
            return 1;
        } else {
            if (!input_file.empty()) {
                std::cerr << "Multiple input files specified" << std::endl;
                show_usage();
                return 1;
            }
            input_file = arg;
        }
    }
    if (input_file.empty()) {
        show_usage();
        return 1;
    }
    try {
        if (g_debug_mode) {
            std::cout << "=== SSB COMPRESSOR DEBUG MODE ===" << std::endl;
            std::cout << "Input file: " << input_file << std::endl;
        }
        auto pe = parse_pe(input_file);
        auto packed = build_ssb_packed(pe);
        std::string out = input_file.substr(0, input_file.find_last_of('.')) + "_packed.exe";
        std::ofstream f(out, std::ios::binary);
        f.write((char*)packed.data(), packed.size());
        f.close();
        if (g_debug_mode) {
            std::cout << "\nPacked " << input_file << " -> " << out << " (SSB format)" << std::endl;
        } else {
            size_t original_size = pe.raw.size();
            size_t final_size = packed.size();
            double compression_ratio = (double)final_size / original_size;
            std::cout << std::endl;
            std::cout << "Original:   " << std::fixed << std::setprecision(1) 
                      << (double)original_size / 1024.0 << "KB" << std::endl;
            std::cout << "Packed:     " << std::fixed << std::setprecision(1) 
                      << (double)final_size / 1024.0 << "KB" << std::endl;
            std::cout << "Compressed: " << std::fixed << std::setprecision(1) 
                      << (compression_ratio * 100.0) << "%" << std::endl;
            std::cout << std::endl;
            std::cout << "Output:     " << out << std::endl;
            std::cout << "Status:     Compression successful!" << std::endl;
        }
    } catch (std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}