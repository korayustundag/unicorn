using System;
using System.IO;
using System.Security.Cryptography;

namespace unicorn
{
    internal class Program
    {
        private static readonly Version version = new Version(1, 0, 0, 0);

        private static void Exit(int code, bool wait = false)
        {
            if (wait)
            {
                Console.Write("Press [enter] to exit...");
                Console.ReadLine();
            }
            Environment.Exit(code);
        }

        private static void WriteError(string message)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.Write("Error: ");
            Console.ResetColor();
            Console.WriteLine(message);
        }

        private static void Encrypt(string filePath, string passwd)
        {
            try
            {
                using (Aes alg = Aes.Create())
                {
                    alg.KeySize = 256;
                    alg.BlockSize = 128;
                    alg.Mode = CipherMode.CBC;
                    alg.Padding = PaddingMode.PKCS7;
                    alg.GenerateIV();
                    byte[] saltData = new byte[16];
                    using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
                    {
                        rng.GetBytes(saltData);
                    }
                    using (Rfc2898DeriveBytes r2db = new Rfc2898DeriveBytes(passwd, saltData, 1000, HashAlgorithmName.SHA256))
                    {
                        alg.Key = r2db.GetBytes(32);
                    }
                    string tempFile = Path.GetTempFileName();
                    using (FileStream sourceFileStream = new FileStream(filePath, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
                    {
                        using (FileStream tempFileStream = new FileStream(tempFile, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
                        {
                            using (CryptoStream cryptoStream = new CryptoStream(tempFileStream, alg.CreateEncryptor(), CryptoStreamMode.Write))
                            {
                                tempFileStream.Write(saltData, 0, saltData.Length);
                                tempFileStream.Write(alg.IV, 0, alg.IV.Length);
                                sourceFileStream.CopyTo(cryptoStream);
                            }
                        }
                    }
                    File.Move(tempFile, filePath, true);
                }
                Console.WriteLine("Encryption process completed!");
            }
            catch (Exception ex)
            {
                WriteError(ex.Message);
            }
        }

        private static void Decrypt(string filePath, string passwd)
        {
            try
            {
                string tempFile = Path.GetTempFileName();
                using (FileStream sourceFileStream = new FileStream(filePath, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
                {
                    byte[] saltData = new byte[16];
                    sourceFileStream.Read(saltData, 0, saltData.Length);
                    byte[] ivData = new byte[16];
                    sourceFileStream.Read(ivData, 0, ivData.Length);
                    using (Aes alg = Aes.Create())
                    {
                        alg.KeySize = 256;
                        alg.BlockSize = 128;
                        alg.Mode = CipherMode.CBC;
                        alg.Padding = PaddingMode.PKCS7;
                        alg.IV = ivData;
                        using (Rfc2898DeriveBytes r2db = new Rfc2898DeriveBytes(passwd, saltData, 1000, HashAlgorithmName.SHA256))
                        {
                            alg.Key = r2db.GetBytes(32);
                        }
                        using (FileStream tempFileStream = new FileStream(tempFile, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
                        {
                            using (CryptoStream cryptoStream = new CryptoStream(sourceFileStream, alg.CreateDecryptor(), CryptoStreamMode.Read))
                            {
                                cryptoStream.CopyTo(tempFileStream);
                            }
                        }
                    }
                }
                File.Move(tempFile, filePath, true);
                Console.WriteLine("Decryption process completed!");
            }
            catch (Exception ex)
            {
                WriteError(ex.Message);
            }
        }

        private static void WelcomeMessage()
        {
            Console.WriteLine("   __  __      _                     ");
            Console.WriteLine("  / / / /___  (_)________  _________ ");
            Console.WriteLine(" / / / / __ \\/ / ___/ __ \\/ ___/ __ \\");
            Console.WriteLine("/ /_/ / / / / / /__/ /_/ / /  / / / /");
            Console.WriteLine("\\____/_/ /_/_/\\___/\\____/_/  /_/ /_/");
            Console.WriteLine();
        }

        private static void Usage()
        {
            WelcomeMessage();
            Console.WriteLine("Version: {0}", version.ToString());
            Console.WriteLine("|===== Encrypt File ======================================|");
            Console.WriteLine("|                                                         |");
            if (!OperatingSystem.IsWindows())
            {
                Console.WriteLine("|   unicorn.exe [-e|--enc] [File Path] [Password]         |");
                Console.WriteLine("|                                                         |");
                Console.WriteLine("|   unicorn.exe -e C:\\Path\\To\\File.ext 1234               |");
                Console.WriteLine("|   unicorn.exe --enc \"C:\\Path\\To\\File Name.ext\" \"1234\"   |");
            }
            else
            {
                Console.WriteLine("|   ./unicorn [-e|--enc] [File Path] [Password]           |");
                Console.WriteLine("|                                                         |");
                Console.WriteLine("|   ./unicorn -e /path/to/file.ext 1234                   |");
                Console.WriteLine("|   ./unicorn --enc \"/path/to/file name.ext\" \"1234\"       |");
            }
            Console.WriteLine("|                                                         |");
            Console.WriteLine("|=========================================================|");
            Console.WriteLine("|                                                         |");
            Console.WriteLine("|===== Decrypt File ======================================|");
            Console.WriteLine("|                                                         |");
            if (!OperatingSystem.IsWindows())
            {
                Console.WriteLine("|   unicorn.exe [-d|--dec] [File Path] [Password]         |");
                Console.WriteLine("|                                                         |");
                Console.WriteLine("|   unicorn.exe -d C:\\Path\\To\\File.ext 1234               |");
                Console.WriteLine("|   unicorn.exe --dec \"C:\\Path\\To\\File Name.ext\" \"1234\"   |");
            }
            else
            {
                Console.WriteLine("|   ./unicorn [-d|--dec] [File Path] [Password]           |");
                Console.WriteLine("|                                                         |");
                Console.WriteLine("|   ./unicorn -d /path/to/file.ext 1234                   |");
                Console.WriteLine("|   ./unicorn --dec \"/path/to/file name.ext\" \"1234\"       |");
            }
            Console.WriteLine("|                                                         |");
            Console.WriteLine("|=========================================================|");
            Console.WriteLine("|                                                         |");
            Console.WriteLine("|  Developer: Koray ÜSTÜNDAĞ                              |");
            Console.WriteLine("|  Home Page: https://github.com/korayustundag/unicorn    |");
            Console.WriteLine("|                                                         |");
            Console.WriteLine("|=========================================================|");
            Exit(0, true);
        }

        static void Main(string[] args)
        {
            Console.Title = "Unicorn";
            if (args.Length == 1)
            {
                if (args[0] == "-h" || args[0] == "--help")
                {
                    Usage();
                }
            }
            
            if (args.Length != 3)
            {
                WriteError("The arguments are not as expected!");
                Console.WriteLine("Use the \"-h or --help\" argument for help.");
                Exit(1, true);
            }

            bool isEnc;
            if (args[0] == "-e" || args[0] == "--enc")
            {
                isEnc = true;
            }
            else if (args[0] == "-d" || args[0] == "--dec")
            {
                isEnc = false;
            }
            else
            {
                WriteError("The arguments are not as expected!");
                Console.WriteLine("Use the \"-h or --help\" argument for help.");
                Exit(1, true);
                return;
            }

            string filePath;
            if (File.Exists(args[1]))
            {
                filePath = args[1];
            }
            else
            {
                WriteError("File not found!");
                Exit(1, true);
                return;
            }

            string pass;
            if (!string.IsNullOrEmpty(args[2]))
            {
                pass = args[2];
            }
            else
            {
                WriteError("Password is empty!");
                Exit(1, true);
                return;
            }

            if (isEnc)
            {
                Encrypt(filePath, pass);
            }
            else
            {
                Decrypt(filePath, pass);
            }
            Exit(0);
        }
    }
}