using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        private string alphabet = "abcdefghijklmnopqrstuvwxyz";
        public string Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();
            plainText =  plainText.ToLower();
            string charsNotInCipher = "";
            string key = "";
            int charNotInCipherIndex = 0;

            for (int char_no = 0; char_no < alphabet.Length; char_no++)
            {
                if (!cipherText.Contains(alphabet[char_no]))
                {
                    charsNotInCipher += alphabet[char_no];
                }
            }


            for (int alphabetChar_no = 0; alphabetChar_no < alphabet.Length; alphabetChar_no++)
            {
                bool charInPlain = false;
                int indexTemp = -1;

                for (int char_no = 0; char_no < plainText.Length; char_no++)
                {
                    if(plainText[char_no] == alphabet[alphabetChar_no])
                    {
                        charInPlain = true;
                        indexTemp = char_no;
                        break;
                    }    
                }

                if(charInPlain)
                {
                    key += cipherText[indexTemp];
                }    

                else
                {
                    key += charsNotInCipher[charNotInCipherIndex];
                    charNotInCipherIndex++;
                }    
            }


            return key;
        }

        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            string plainText = "";
            char charTemp;
            int charIndexInKey;

            // 97 is the ascii of char a
            for (int char_no = 0; char_no < cipherText.Length; char_no++)
            {
                charTemp = cipherText[char_no];
                charIndexInKey = key.IndexOf(charTemp);
                charIndexInKey += 97;
                plainText += Convert.ToChar(charIndexInKey);
            }


            return plainText;
        }

        public string Encrypt(string plainText, string key)
        {
            plainText = plainText.ToLower();
            string cipherText = "";
            char charTemp;
            int keyIndex;

            // 97 is the ascii of char a
            for (int char_no = 0; char_no < plainText.Length; char_no++)
            {
                charTemp = plainText[char_no];
                keyIndex = charTemp - 97;
                cipherText += key[keyIndex];    
            }


            return cipherText;
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
            cipher = cipher.ToLower();
            string freqInCipher = "";
            string freqInEnglish = "ETAOINSRHLDCUMFPGWYBVKXJQZ";
            Dictionary<char,double> charsFrequency = new Dictionary<char, double>();
            

            for (int char_no = 0; char_no < alphabet.Length; char_no++)
            {
                charsFrequency.Add(alphabet[char_no], 0.0);
            }

            for (int char_no = 0; char_no < cipher.Length; char_no++)
            {
                charsFrequency[cipher[char_no]]++;
            }

            for (int char_no = 0; char_no < alphabet.Length; char_no++)
            {
                char temp = Convert.ToChar(char_no + 97);
                charsFrequency[temp] = (charsFrequency[temp] * 100) / cipher.Length;
            }

            char charWithHeighstFreq;
            for (int char_no = 0; char_no < alphabet.Length; char_no++)
            {
                charWithHeighstFreq = charsFrequency.Aggregate((x, y) => x.Value > y.Value ? x : y).Key;
                charsFrequency[charWithHeighstFreq] = -1;
                freqInCipher += charWithHeighstFreq;
            }

            string key = Analyse(freqInEnglish.ToLower(), freqInCipher);

            return Decrypt(cipher, key);
        }
    }
}
