using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
        /*
         * let letters be indexed from 0 to 25
         * C.T index = (P.T index + key index) mod 26
         * No need to construct a vigenere tableau
        */
        public string Analyse(string plainText, string cipherText)
        {
            // repeated key = (ct - pt) % 26
            string repeatedKey = Decrypt(cipherText, plainText);
            string key = "";
            int index = 0;
            key += repeatedKey[index++];

            while (!Encrypt(plainText, key).Equals(cipherText, StringComparison.InvariantCultureIgnoreCase)) 
            {
                key += repeatedKey[index++];
            }
            return key;
        }

        public string Decrypt(string cipherText, string key)
        {
            string PT = "";
            key = repeatKey(key, cipherText.Length);
            for(int i=0;i<key.Length;i++)
            {
                PT += unSubistitute(cipherText[i], key[i]);
            }
            return PT;
        }

        public string Encrypt(string plainText, string key)
        {
            string CT = "";
            key = repeatKey(key, plainText.Length);
            for(int i =0;i<plainText.Length;i++)
            {
                CT += Subistitute(plainText[i], key[i]);
            }
            return CT;
        }
        private char Subistitute(char p, char k)
        {
            // ct = (pt+key)%26
            int PT_index = GetAlphabeticalPosition(p);
            int Key_index = GetAlphabeticalPosition(k);
            int cipher_index = (PT_index + Key_index) % 26;
            return (char)(cipher_index + 97);
        }
        private char unSubistitute(char c, char k)
        {
            // pt = (ct-key) % 26
            int cipher_index = GetAlphabeticalPosition(c);
            int Key_index = GetAlphabeticalPosition(k);
            int PT_index = ((cipher_index+26) - Key_index) % 26;
            return (char)(PT_index + 97);
        }
        private string repeatKey(string key, int length)
        {
            string repeatedKey = "";
            int index = 0;
            while(repeatedKey.Length<length)
            {
                repeatedKey += key[index++ % key.Length];
            }
            return repeatedKey;
        }
        private int GetAlphabeticalPosition(char ch)
        {
            return ((int)ch < 97 ? (int)ch - 65 : (int)ch - 97);
        }
    }
}