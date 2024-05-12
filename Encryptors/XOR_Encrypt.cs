using System;

class Encryptor
{
    static void Main()
    {
        byte[] shellcode = new byte[] {};

        byte[] key = new byte[] { 0x1A, 0x87, 0x52, 0xFC, 0x78, 0xD1, 0xFE, 0x16, 0xD6, 0x87, 0xC7, 0x83, 0xF0, 0x11, 0x5E, 0xAC };

        byte[] encryptedShellcode = EncryptDecrypt(shellcode, key);

        Console.Write("byte[] encryptedShellcode = new byte[] { ");
        for (int i = 0; i < encryptedShellcode.Length; i++)
        {
            Console.Write($"0x{encryptedShellcode[i]:X2}");
            if (i < encryptedShellcode.Length - 1)
                Console.Write(", ");
        }
        Console.WriteLine(" };");
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
