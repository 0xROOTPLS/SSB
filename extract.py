import struct, sys

def extract_sections_pe(data: bytes, wanted=("text", "rdata", "data")):
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    num_sections = struct.unpack_from("<H", data, pe_offset+6)[0]
    opt_size = struct.unpack_from("<H", data, pe_offset+20)[0]

    # Entry RVA from opt header
    entry_rva = struct.unpack_from("<I", data, pe_offset+40)[0]
    print(f"PE Entry RVA: 0x{entry_rva:X} (this is stub_main since /entry:stub_main)")

    sect_off = pe_offset + 24 + opt_size
    sections = {}
    text_section_rva = None

    for i in range(num_sections):
        off = sect_off + i*40
        name = data[off:off+8].rstrip(b"\x00").decode("ascii","ignore")
        virt_size = struct.unpack_from("<L", data, off+8)[0]
        virt_addr = struct.unpack_from("<L", data, off+12)[0]
        raw_size  = struct.unpack_from("<L", data, off+16)[0]
        raw_ptr   = struct.unpack_from("<L", data, off+20)[0]

        if name.lstrip(".") in wanted and raw_size > 0 and raw_ptr > 0:
            print(f"Found {name}: RVA 0x{virt_addr:X}, raw_size {raw_size}, file offset 0x{raw_ptr:X}")
            section_data = data[raw_ptr:raw_ptr+raw_size]
            sections[name.lstrip(".")] = {
                "rva": virt_addr,
                "data": section_data,
                "raw_size": raw_size,
                "virt_size": virt_size
            }
            if name.lstrip(".") == "text":
                text_section_rva = virt_addr

    if not text_section_rva:
        print("ERROR: No .text found")
        sys.exit(1)

    # Compute total blob size --> last section end RVA - text RVA
    max_end_rva = max(s["rva"] + s["virt_size"] for s in sections.values())
    blob_size = max_end_rva - text_section_rva
    blob = bytearray(blob_size)

    # Place each section at section RVA - text RVA
    for name, s in sections.items():
        dest_off = s["rva"] - text_section_rva
        blob[dest_off:dest_off+len(s["data"])] = s["data"]
        if b'\xEF\xBE\xAD\xDE' in s["data"]:
            pos = s["data"].find(b'\xEF\xBE\xAD\xDE')
            print(f"  -> {name} contains DEADBEEF at section offset 0x{pos:X}")

    # Calculate stub_main offset relative to blob
    stub_main_offset = entry_rva - text_section_rva
    print(f"\nCalculated stub_main offset in blob: 0x{stub_main_offset:X}")
    print(f"  Entry RVA (0x{entry_rva:X}) - Text RVA (0x{text_section_rva:X}) = 0x{stub_main_offset:X}")

    return bytes(blob), stub_main_offset

def dump_bytes_to_header(all_data: bytes, entry_offset: int):
    deadbeef_pos = all_data.find(b'\xEF\xBE\xAD\xDE')
    if deadbeef_pos != -1:
        print(f"\nDEADBEEF found at blob offset 0x{deadbeef_pos:X}")
        print(f"Distance from stub_main to DEADBEEF: 0x{deadbeef_pos-entry_offset:X} bytes")
    else:
        print("\nWARNING: DEADBEEF pattern not found in blob!")

    with open("stub_bytes.h", "w") as out:
        out.write("// Generated stub machine code\n")
        out.write("unsigned char stub_bytes[] = {\n    ")
        for i, b in enumerate(all_data):
            if i and i % 16 == 0:
                out.write("\n    ")
            out.write(f"0x{b:02X}")
            if i != len(all_data)-1:
                out.write(", ")
        out.write("\n};\n")
        out.write(f"size_t stub_size = {len(all_data)};\n")
        out.write(f"unsigned int stub_entry_rva = 0x{entry_offset:X};\n")

    print(f"\nWrote stub_bytes.h ({len(all_data)} bytes)")
    print(f"stub_entry_rva = 0x{entry_offset:X} ({entry_offset} decimal)")

def main(path):
    with open(path,"rb") as f:
        data=f.read()
    if data[0:2] != b"MZ":
        print("ERROR: Not a PE file")
        sys.exit(1)

    print(f"Parsing {path} as PE/EXE")
    blob, entry_off = extract_sections_pe(data)
    print(f"\nExtracted blob size: {len(blob)} bytes")
    dump_bytes_to_header(blob, entry_off)
    print("\nDone!")

if __name__ == "__main__":
    if len(sys.argv)!=2:
        print("Usage: extract.py <stub.exe>")
        sys.exit(1)
    main(sys.argv[1])
