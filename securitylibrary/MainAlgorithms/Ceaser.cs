using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        public string Encrypt(string plainText, int key)
        {

            int length = plainText.Length;

            plainText = plainText.ToLower();

            StringBuilder cipherBuilder = new StringBuilder(length);

            for (int i = 0; i < length; i++)
            {
                int encrypted = ((int)plainText[i] - 'a' + key);

                // this is done so that the same function can
                // be used for encryption and decryption
                if (encrypted < 0)
                    encrypted += 26;
                else
                    encrypted %= 26;


                encrypted += 'a';


                cipherBuilder.Append((char)encrypted);
            }

            string cipher = cipherBuilder.ToString();

            return cipher;
        }

        public string Decrypt(string cipherText, int key)
        {
            return Encrypt(cipherText, -key);
        }

        public int Analyse(string plainText, string cipherText)
        {
            if (plainText.Equals(cipherText, StringComparison.InvariantCultureIgnoreCase))
                return 0;

            int key = -1;

            for (int i = 1; i < 26; i++)
            {
                string decryptedText = Decrypt(cipherText, i);

                if (decryptedText.Equals(plainText, StringComparison.InvariantCultureIgnoreCase))
                {
                    key = i;
                    break;
                }
            }
            return key;
        }
    }
}
