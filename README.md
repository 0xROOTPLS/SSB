# Save Some Bytes (SSB)
**PE Compression for Windows x64 Executables**

SSB is a PE packer that reduces executable file sizes while preserving full functionality. It implements custom LZSS compression with PE structure preservation.
## Features
- **Custom LZSS Compression**: Achieves 30-60% compression ratios on typical executables
- **Full PE Preservation**: Maintains all PE structures including:
  - Import/Export tables
  - Resources (manifests, icons, etc.)
  - TLS callbacks
  - Exception handlers (SEH/CFG)
  - Debug information
  - Digital signatures
  - Load configuration
- **Fast Decompression**: Optimized LZSS with 8-byte chunk processing
- **Self-Contained Stub**: No external dependencies, pure Windows API usage
- **ASLR/DEP Compatible**: Works with all modern Windows security features
## Installation
### Prerequisites
- Windows 10/11 x64
- Visual Studio 2019 or later
### Building from Source
Using MSVC:
```batch
cl /O2 /EHsc ssb.cpp /Fe:ssb.exe
```
## Usage
### Basic Compression
```batch
ssb input.exe
```
This creates `input_packed.exe`.
### Debug Mode
```batch
ssb --debug input.exe
```
Shows detailed analysis of PE structures and compression statistics.
## Compatibility
**Important**: SSB works reliably with console applications and most basic GUI programs. Some complex GUI applications may not function correctly after packing due to advanced runtime requirements. Always test packed executables thoroughly before distribution.
## How It Works
SSB uses a two-stage architecture:
1. **Compression Stage** (`ssb.exe`)
   - Analyzes PE structure
   - Extracts and preserves critical directories
   - Compresses sections using LZSS
   - Builds new PE with embedded stub
2. **Decompression Stub** (embedded)
   - Minimal runtime unpacker
   - Resolves APIs without IAT
   - Decompresses to memory
   - Restores PE directories
   - Transfers control to original entry point
## Technical Details
### Compression Algorithm
- **LZSS** with 4KB sliding window
- 3-18 byte match lengths
- Optimized for x64 with 8-byte chunk comparisons
- Typical compression ratios: 30-60% of original size
### PE Structure Handling
- Preserves all data directories
- Maintains section characteristics
- Handles relocations for ASLR
- Supports TLS callbacks
- Restores SEH/CFG tables
- Keeps manifest resources
### Stub Implementation
- Pure C++ stub
- No CRT dependencies
- Manual PEB traversal for DLL resolution
- Dynamic API resolution
- ~8KB overhead
## Limitations
- **x64 only**: Currently supports only 64-bit PE files
- **Size limit**: Maximum 32 sections per executable
- **GUI compatibility**: Some complex GUI programs may not work after packing
  
**Note**: Packed executables may trigger false positives in some antivirus software. This is common with all packers. Consider signing your packed executables with a code signing certificate.

## Contributing
Contributions are welcome! Areas of interest:
- x86 (32-bit) support
- Alternative compression algorithms
- Better GUI support
---
*Save Some Bytes - Because every byte counts.*
