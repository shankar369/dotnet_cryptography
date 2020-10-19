using System;
using System.Security.Cryptography;
using Konscious.Security.Cryptography;
using System.Text;
using System.Linq;

namespace cryptography_dotnet
{
    public class Argon2Hash
    {
        public byte[] GenerateSalt()
        {
            const int saltLength = 32;

            using (var randomNumberGenerator = new RNGCryptoServiceProvider())
            {
                var randomNumber = new byte[saltLength];
                randomNumberGenerator.GetBytes(randomNumber);

                return randomNumber;
            }

        }

        public byte[] HashPassword(string password, byte[] salt)
        {
            var argon2 = new Argon2id(Encoding.UTF8.GetBytes(password));

            argon2.Salt = salt;
            argon2.DegreeOfParallelism = 16; // four cores
            argon2.Iterations = 400;
            argon2.MemorySize = 8192; // 1 GB

            return argon2.GetBytes(32);
        }

        public bool VerifyHash(string password, byte[] salt, byte[] hash)
        {
            var newHash = HashPassword(password, salt);
            return hash.SequenceEqual(newHash);
        }
    }
}