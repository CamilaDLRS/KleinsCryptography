using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace CryptographyKlen
{
    /// <summary>
    /// Create by Camila Delarosa, based on Carlos Klein code
    /// Date: 16/02/2022
    /// </summary>
    class Program
    {
        static void Main(string[] args)
        {
            string action;
            string EncryptionKey;

            Console.WriteLine("WELCOME TO CRYPTOGRAPHY OF KLEIN");
            do
            {
                Console.WriteLine("\nTo encrypt, type 0\nTo decrypt, type 1,\nTo close program, type 2");
                action = Console.ReadLine();

                if (action == "2")
                    Environment.Exit(0);

                try
                {
                    if (action == "0")
                    {
                        Console.WriteLine("\nType de EncryptionKey");
                        EncryptionKey = Console.ReadLine();

                        Console.WriteLine("\nType it the text that you want to encrypt:");
                        string text = Console.ReadLine();
                        Console.WriteLine("\n" + Encrypt(text, EncryptionKey));
                    }
                    else if (action == "1")
                    {
                        Console.WriteLine("\nType de EncryptionKey");
                        EncryptionKey = Console.ReadLine();

                        Console.WriteLine("\nType it the text that you want to decrypt:");
                        string text = Console.ReadLine();
                        Console.WriteLine("\n" + Decrypt(text, EncryptionKey));
                    }
                }
                catch (Exception)
                {
                    Console.WriteLine("\nInvalid informations... try again");
                }               

            } while (true);
        }

        public static string Encrypt(string clearText, string EncryptionKey)
        {
            byte[] clearBytes = Encoding.Unicode.GetBytes(clearText);
            using (Aes encryptor = Aes.Create())
            {
                Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(EncryptionKey, new byte[] { 0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76 });
                encryptor.Key = pdb.GetBytes(32);
                encryptor.IV = pdb.GetBytes(16);
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(clearBytes, 0, clearBytes.Length);
                        cs.Close();
                    }
                    clearText = Convert.ToBase64String(ms.ToArray());
                }
            }
            return clearText;
        }

        public static string Decrypt(string cipherText, string EncryptionKey)
        {
            cipherText = cipherText.Replace(" ", "+");
            byte[] cipherBytes = Convert.FromBase64String(cipherText);
            using (Aes encryptor = Aes.Create())
            {
                Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(EncryptionKey, new byte[] { 0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76 });
                encryptor.Key = pdb.GetBytes(32);
                encryptor.IV = pdb.GetBytes(16);
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(cipherBytes, 0, cipherBytes.Length);
                        cs.Close();
                    }
                    cipherText = Encoding.Unicode.GetString(ms.ToArray());
                }
            }
            return cipherText;
        }
    }
}