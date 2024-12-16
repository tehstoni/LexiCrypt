# LexiCrypt
**LexiCrypt** is a shellcode obfuscation and encoding tool that transforms raw shellcode bytes into a "lexicon" of words derived from file names in the windows system32 directory, the /usr/bin directory on linux, or use a randomly generated list at runtime. The resulting encoded output can then be embedded into a code template in various programming languages (e.g., C++, Rust, C#, Go, VBScript/WScript). This approach can help disguise shellcode and potentially bypass naive detection mechanisms.

## How It Works
1. **Wordlist Generation**:  
   LexiCrypt scans a directory (Windows default is: `C:\Windows\System32`, Linux default is: `/usr/bin/`) to gather a large set of unique filenames (without extensions). From these filenames, it selects and shuffles 256 unique words. Each unique word maps to a single byte (`0x00` to `0xFF`).
   Its also capible of ingesting custom wordlist (`-w`), and generating its own random as well with the `-r` flag.
   

3. **Shellcode Encoding**:  
   Given a raw shellcode file (e.g., a binary blob of machine code), LexiCrypt replaces each byte with a corresponding word from the 256-word dictionary. For example, if byte `0x41` corresponds to the word `"notepad"`, that byte is replaced with `"notepad"` in the encoded output.

4. **Output Templates**:  
   After encoding, LexiCrypt generates a code template that includes the encoded words and the dictionary. Depending on the chosen language template (e.g., `cpp`, `rust`, `csharp`, `go`, `powershell`(p/invoke), and `powershell_alt` (reflection)), it produces a ready-to-compile (or run) snippet.
   This snippet (TLDR basic CreateThread process injection):
   - Decodes the word-based shellcode back into a byte array at runtime.
   - Allocates executable memory.
   - Copies and executes the decoded shellcode via `VirtualAlloc` and `CreateThread` (on Windows).

## Features
- **Multi-language templates**: Currently supports C++, Rust, C#, Go, and Powershell templates for output.
- **Automated wordlist generation**: Dynamically generates a 256-word dictionary from system filenames.
- **Verification step**: Automatically verifies that the encoded shellcode correctly decodes back to the original bytes.
- **Evasion technique**: By representing shellcode bytes as words, it may help avoid straightforward signature-based detection.

## Requirements
- **Rust Toolchain**:  
  You’ll need a Rust compiler and Cargo.
  
- **Windows environment**:  
  LexiCrypt currently relies on Windows-specific APIs and directories.

Go installed is also needed if you decide to compile the Go output.

## Installation
1. **Clone the Repository**:  
```
 git clone https://github.com/<your-username>/LexiCrypt.git
 cd LexiCrypt
```
Build the Project:

```
cargo build --release
```
This produces a binary in target/release/lexiCrypt.exe.

## Usage
Basic command-line usage:

```
lexicrypt.exe -i path\to\input_shellcode.bin -o path\to\output_file.ext -t cpp
```

Arguments:
  ```
    -i, --input <INPUT_FILE>: Path to the input shellcode file (raw binary).
    -o, --output <OUTPUT_FILE>: Path to the output file (the generated template code).
    -t, --template <TEMPLATE>: The template format. Supported templates include:
        cpp
        rust
        csharp
        go
    -r, --random: Enables random wordlist generation.
    -w, --wordlist: Ingest a custom wordlist by the user. (must be at least 256 unique lines in length) 
  ```
Example:

```
lexicrypt.exe -i shellcode.bin -o lexiloader.cpp -t cpp 
```

This command reads shellcode.bin, generates a 256-word dictionary from C:\Windows\System32, encodes the shellcode, and produces decoded_shellcode.cpp, containing the encoded words and a decoder routine.
Output and Execution

After running LexiCrypt, you’ll have a single source file in your chosen language template.

For example, if you chose cpp, you’ll get a .cpp file. You can then compile it:

```
cl .\lexiloader.cpp /EHsc /Od /bigobj

.\lexiloader.exe
```

Running lexiloader.exe will:
    Print information about decoding.
    Allocate memory, copy in the decoded shellcode.
    Create a thread to execute it.

For rust, you will need to add the following dependency to your Cargo.toml
```
windows = "0.58.0"
```

Can automate it by running the following command while in the directory of your project:
```
cargo add windows
```

