using System;
using System.Security.Cryptography;

namespace cryptography_dotnet
{
    public class HashingWithSalt
    {
        public static byte[] GenerateSalt()
        {
            const int saltLength = 32;

            using (var randomNumberGenerator = new RNGCryptoServiceProvider())
            {
                var randomNumber = new byte[saltLength];
                randomNumberGenerator.GetBytes(randomNumber);

                return randomNumber;
            }


        }
        public static byte[] Combine(byte[] first, byte[] second)
        {
            var res = new byte[first.Length + second.Length];

            Buffer.BlockCopy(first, 0, res, 0, first.Length);
            Buffer.BlockCopy(second, 0, res, first.Length, second.Length);

            return res;
        }

        public static byte[] HashPasswordWithSalt(byte[] toBeHashed, byte[] salt)
        {
            using (var sha512 = SHA512.Create())
            {
                return sha512.ComputeHash(Combine(toBeHashed, salt));
            }
        }
    }
}