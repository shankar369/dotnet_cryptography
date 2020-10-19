using System;
using System.Text;
using System.Diagnostics;

namespace cryptography_dotnet
{
    class Program
    {
        public static void randomNumbers()
        {
            Console.WriteLine("Random number demonstration in dotnet");
            Console.WriteLine("--------------------------------------");
            Console.WriteLine();
            for (var i = 0; i < 10; i++)
            {
                Console.WriteLine("Random Number " + (i + 1) + " : " + Convert.ToBase64String(Random.GenerateRandomNumber(32)));
            }
        }

        public static void hashing()
        {
            const string originalMessage1 = "password";
            const string originalMessage2 = "Secure*123";

            Console.WriteLine("\n\nHasing in dotnet");
            Console.WriteLine("--------------------");
            Console.WriteLine();
            Console.WriteLine("Original Message 1: " + originalMessage1);
            Console.WriteLine("Original Message 2: " + originalMessage2);
            Console.WriteLine();

            var md5HashedMessage1 = Convert.ToBase64String(HashData.ComputeHashMd5(Encoding.UTF8.GetBytes(originalMessage1)));
            var md5HashedMessage2 = Convert.ToBase64String(HashData.ComputeHashMd5(Encoding.UTF8.GetBytes(originalMessage2)));

            var sha1HashedMessage1 = Convert.ToBase64String(HashData.ComputeHashSha1(Encoding.UTF8.GetBytes(originalMessage1)));
            var sha1HashedMessage2 = Convert.ToBase64String(HashData.ComputeHashSha1(Encoding.UTF8.GetBytes(originalMessage2)));

            var sha256HashedMessage1 = Convert.ToBase64String(HashData.ComputeHashSha256(Encoding.UTF8.GetBytes(originalMessage1)));
            var sha256HashedMessage2 = Convert.ToBase64String(HashData.ComputeHashSha256(Encoding.UTF8.GetBytes(originalMessage2)));

            var sha512HashedMessage1 = Convert.ToBase64String(HashData.ComputeHashSha512(Encoding.UTF8.GetBytes(originalMessage1)));
            var sha512HashedMessage2 = Convert.ToBase64String(HashData.ComputeHashSha512(Encoding.UTF8.GetBytes(originalMessage2)));

            Console.WriteLine("MD5 : ");
            Console.WriteLine(md5HashedMessage1);
            Console.WriteLine(md5HashedMessage2);
            Console.WriteLine();

            Console.WriteLine("SHA1 : ");
            Console.WriteLine(sha1HashedMessage1);
            Console.WriteLine(sha1HashedMessage2);
            Console.WriteLine();

            Console.WriteLine("SHA256 : ");
            Console.WriteLine(sha256HashedMessage1);
            Console.WriteLine(sha256HashedMessage2);
            Console.WriteLine();

            Console.WriteLine("SHA512 : ");
            Console.WriteLine(sha512HashedMessage1);
            Console.WriteLine(sha512HashedMessage2);
            Console.WriteLine();

        }

        public static void hmac()
        {
            const string originalMessage1 = "Original Message to hash";
            const string originalMessage2 = "Or1ginal Message to hash";

            Console.WriteLine("\n\nHasing in dotnet");
            Console.WriteLine("--------------------");
            Console.WriteLine();
            Console.WriteLine("Original Message 1: " + originalMessage1);
            Console.WriteLine("Original Message 2: " + originalMessage2);
            Console.WriteLine();

            var key = HMAC.GenerateKey();

            var md5HashedMessage1 = Convert.ToBase64String(HMAC.ComputeHmacMD5(Encoding.UTF8.GetBytes(originalMessage1), key));
            var md5HashedMessage2 = Convert.ToBase64String(HMAC.ComputeHmacMD5(Encoding.UTF8.GetBytes(originalMessage2), key));

            var sha1HashedMessage1 = Convert.ToBase64String(HMAC.ComputeHmacSHA1(Encoding.UTF8.GetBytes(originalMessage1), key));
            var sha1HashedMessage2 = Convert.ToBase64String(HMAC.ComputeHmacSHA1(Encoding.UTF8.GetBytes(originalMessage2), key));

            var sha256HashedMessage1 = Convert.ToBase64String(HMAC.ComputeHmacSHA256(Encoding.UTF8.GetBytes(originalMessage1), key));
            var sha256HashedMessage2 = Convert.ToBase64String(HMAC.ComputeHmacSHA256(Encoding.UTF8.GetBytes(originalMessage2), key));

            var sha512HashedMessage1 = Convert.ToBase64String(HMAC.ComputeHmacSHA512(Encoding.UTF8.GetBytes(originalMessage1), key));
            var sha512HashedMessage2 = Convert.ToBase64String(HMAC.ComputeHmacSHA512(Encoding.UTF8.GetBytes(originalMessage2), key));

            Console.WriteLine("HMAC MD5 : ");
            Console.WriteLine(md5HashedMessage1);
            Console.WriteLine(md5HashedMessage2);
            Console.WriteLine();

            Console.WriteLine("HMAC SHA1 : ");
            Console.WriteLine(sha1HashedMessage1);
            Console.WriteLine(sha1HashedMessage2);
            Console.WriteLine();

            Console.WriteLine("HMAC SHA256 : ");
            Console.WriteLine(sha256HashedMessage1);
            Console.WriteLine(sha256HashedMessage2);
            Console.WriteLine();

            Console.WriteLine("HMAC SHA512 : ");
            Console.WriteLine(sha512HashedMessage1);
            Console.WriteLine(sha512HashedMessage2);
            Console.WriteLine();

        }

        public static void hashWithSalt()
        {
            const string password = "password123";
            byte[] salt = HashingWithSalt.GenerateSalt();

            Console.WriteLine("Hashing using salt : ");
            Console.WriteLine("---------------------");
            Console.WriteLine("Password : " + password);
            Console.WriteLine("Salt : " + Convert.ToBase64String(salt));
            Console.WriteLine();

            var hashedPasswordWithSalt = HashingWithSalt.HashPasswordWithSalt(
                Encoding.UTF8.GetBytes(password), salt
            );
            Console.WriteLine("Hashed Password with Salt : " + Convert.ToBase64String(hashedPasswordWithSalt));

        }

        public static void HashPassword(string passwordToHash, int numberOfIterations)
        {
            var sw = new Stopwatch();

            sw.Start();

            var hashedPassword = Pbkdf2.HashPassword(Encoding.UTF8.GetBytes(passwordToHash), Pbkdf2.GenerateSalt(), numberOfIterations);
            sw.Stop();

            Console.WriteLine();
            Console.WriteLine("HashedPassword : " + Convert.ToBase64String(hashedPassword));
            Console.WriteLine("Iterations <" + numberOfIterations + "> Elapsed Time " + sw.ElapsedMilliseconds + "ms");
        }
        public static void pbkdf2Function()
        {
            const string password = "password123";

            Console.WriteLine("Password Based Key Derivation Function in dotnet");
            Console.WriteLine("------------------------------------------------");
            Console.WriteLine("Password to hash : " + password);

            HashPassword(password, 100);
            HashPassword(password, 1000);
            HashPassword(password, 10000);
            HashPassword(password, 50000);
            HashPassword(password, 100000);
            HashPassword(password, 200000);
            HashPassword(password, 500000);
        }

        public static void Des()
        {
            var des = new DesEncryption();
            var key = des.GenerateRandomNumber(8);
            var iv = des.GenerateRandomNumber(8);
            const string original = "Text to encrypt";

            var encrypted = des.Encrypt(Encoding.UTF8.GetBytes(original), key, iv);
            var decrypted = des.Decrypt(encrypted, key, iv);

            var decryptedMessage = Encoding.UTF8.GetString(decrypted);

            Console.WriteLine("DES Encryption in dotnet : ");
            Console.WriteLine("---------------------------");
            Console.WriteLine("Original Text : " + original);
            Console.WriteLine("Encrypted Text : " + Convert.ToBase64String(encrypted));
            Console.WriteLine("Decrypted Text : " + decryptedMessage);
        }
        public static void TripleDes()
        {
            var des = new TripleDesEncryption();
            var key = des.GenerateRandomNumber(24); //it will split into 3 keys 8 8 8 
            //var key = des.GenerateRandomNumber(16);
            var iv = des.GenerateRandomNumber(8);
            const string original = "Text to encrypt";

            var encrypted = des.Encrypt(Encoding.UTF8.GetBytes(original), key, iv);
            var decrypted = des.Decrypt(encrypted, key, iv);

            var decryptedMessage = Encoding.UTF8.GetString(decrypted);

            Console.WriteLine("TripleDES Encryption in dotnet : ");
            Console.WriteLine("---------------------------");
            Console.WriteLine("Original Text : " + original);
            Console.WriteLine("Encrypted Text : " + Convert.ToBase64String(encrypted));
            Console.WriteLine("Decrypted Text : " + decryptedMessage);
        }
        public static void Aes()
        {
            var aes = new AesEncryption();
            var key = aes.GenerateRandomNumber(32);
            var iv = aes.GenerateRandomNumber(16);
            const string original = "Text to encrypt";

            var encrypted = aes.Encrypt(Encoding.UTF8.GetBytes(original), key, iv);
            var decrypted = aes.Decrypt(encrypted, key, iv);

            var decryptedMessage = Encoding.UTF8.GetString(decrypted);

            Console.WriteLine("AES Encryption in dotnet : ");
            Console.WriteLine("---------------------------");
            Console.WriteLine("key: " + Convert.ToBase64String(key));
            Console.WriteLine("iv: " + Convert.ToBase64String(iv));
            Console.WriteLine("Original Text : " + original);
            Console.WriteLine("Encrypted Text : " + Convert.ToBase64String(encrypted));
            Console.WriteLine("Decrypted Text : " + decryptedMessage);
        }
        public static void argon2()
        {
            var argon2Hasher = new Argon2Hash();
            var password = "Hello World!";
            var stopwatch = Stopwatch.StartNew();

            Console.WriteLine($"Creating hash for password '{ password }'.");

            var salt = argon2Hasher.GenerateSalt();
            Console.WriteLine($"Using salt '{ Convert.ToBase64String(salt) }'.");

            var hash = argon2Hasher.HashPassword(password, salt);
            Console.WriteLine($"Hash is '{ Convert.ToBase64String(hash) }'.");

            stopwatch.Stop();
            Console.WriteLine($"Process took { stopwatch.ElapsedMilliseconds / 1024.0 } s");

            stopwatch = Stopwatch.StartNew();
            Console.WriteLine($"Verifying hash...");

            var success = argon2Hasher.VerifyHash(password, salt, hash);
            Console.WriteLine(success ? "Success!" : "Failure!");

            stopwatch.Stop();
            Console.WriteLine($"Process took { stopwatch.ElapsedMilliseconds / 1024.0 } s");
        }
        static void Main(string[] args)
        {
            //Console.WriteLine("hello");
            //randomNumbers();
            //hashing();
            //hmac();
            //hashWithSalt();
            //pbkdf2Function();
            //Des();
            //TripleDes();
            //Aes();
            argon2();
        }
    }
}
