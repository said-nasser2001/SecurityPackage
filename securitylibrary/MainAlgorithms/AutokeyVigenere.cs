using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            string key = Decrypt(cipherText, plainText).Remove(cipherText.Length - 1);

            while(!Encrypt(plainText, key).Equals(cipherText, StringComparison.InvariantCultureIgnoreCase))
            {
                key = key.Remove(key.Length - 1);
            }
            return key;
        }
        public string Decrypt(string cipherText, string key)
        {
            string PT = "";
            int ptr = 0;
            for (int i = 0; i < cipherText.Length; i++)
            {
                PT += unSubistitute(cipherText[i], key[i]);
                if (i == key.Length - 1)
                    key += PT[ptr++];
            }
            return PT;
        }
        public string Encrypt(string plainText, string key)
        {
            string CT = "";
            key = getAutoKey(key, plainText, plainText.Length);
            for (int i = 0; i < plainText.Length; i++)
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
            int PT_index = ((cipher_index + 26) - Key_index) % 26;
            return (char)(PT_index + 97);
        }
        private string getAutoKey(string key, string pt, int length)
        {
            string autokey = key;
            int index = 0;
            while (autokey.Length < length)
            {
                autokey += pt[index++];
            }
            return autokey;
        }
        private int GetAlphabeticalPosition(char ch)
        {
            return ((int)ch < 97 ? (int)ch - 65 : (int)ch - 97);
        }
    }
}
