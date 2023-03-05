using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            for (int i = 0; i < plainText.Length; i++)
            {
                if (cipherText.ToUpper().Equals(Encrypt(plainText, i), StringComparison.InvariantCultureIgnoreCase))
                    return i;
            }
            return -1;
        }
        

        public string Decrypt(string cipherText, int key)
        {
            int cipherTextlen = cipherText.Length;
            int coulmnLength = (int)Math.Ceiling((double)cipherText.Length / key);
            char[] plainText = new char[cipherText.Length + 10];


            for (int i = 0; i < key; i++)
            {
                for (int j = 0; j < coulmnLength; j++)
                {
                    if (cipherTextlen == 0)
                        break;
                    plainText[j*key+i] = cipherText[j + coulmnLength * i];
                    cipherTextlen--;
                }
            }
            return new string(plainText).ToUpper();
        }
    
        public string Encrypt(string plainText, int key)
        {
            int plainTextlen=plainText.Length;
            int coulmnLength = (int)Math.Ceiling((double)plainText.Length/ key);
            char[] cipherText = new char[plainText.Length+key];
            

            for (int i = 0; i < coulmnLength; i++)
            { 
                for (int j = 0; j < key; j++)
                {
                    if (plainTextlen == 0)
                        break;
                    cipherText[coulmnLength*j+i] =plainText[j + key * i];
                    plainTextlen--;
                }
            }
            return new string(cipherText).ToUpper();
        }
    }
}
