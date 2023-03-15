using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToUpper();
            cipherText = cipherText.ToUpper();
            List<int> result =new List<int>();
            for (int i = 2; i < plainText.Length; i++)
            {
               
                result = new List<int>(i);
                int len = cipherText.Length;

                int NumberOfCoulmns = i;
                int NumberOfRows = (int)Math.Ceiling((double)cipherText.Length / NumberOfCoulmns);
                Char[,] plainT = new Char[NumberOfCoulmns, NumberOfRows];
                Char[] plainCoulmn = new Char[NumberOfRows];

                for (int k= 0; k < NumberOfRows; k++)
                {
                    for (int j = 0; j < NumberOfCoulmns; j++)
                    {
                        if (len == 0)
                            break;
                        plainT[j, k] = plainText[j + k * NumberOfCoulmns];
                        len--;
                
                    }
                }

                for (int k = 0; k < NumberOfCoulmns; k++)
                {
                    for (int j = 0; j < NumberOfRows; j++)
                    {
                        plainCoulmn[j] = plainT[k,j];
                    }
                    int key = cipherText.IndexOf(new String(plainCoulmn))/ NumberOfRows;
                    if (key != -1)
                        result.Add(key+1);

                }
                if (cipherText.Equals(Encrypt(plainText,result), StringComparison.InvariantCultureIgnoreCase))
                    return result;

            }

            return result;
        }

        public string Decrypt(string cipherText, List<int> key)
        {

            int cipherTextlen = cipherText.Length;
            int NumberOfCoulmns = key.Count;
            int NumberOfRows = (int)Math.Ceiling((double)cipherText.Length / NumberOfCoulmns);
            Char[,] plainText = new Char[NumberOfCoulmns, NumberOfRows];
            for (int i = 0; i < NumberOfCoulmns; i++)
            {
                for (int j = 0; j < NumberOfRows; j++)
                {
                    if (cipherTextlen == 0)
                        break;
                    plainText[i, j] = cipherText[j + i * NumberOfRows];
                    cipherTextlen--;
                }
            }

            char[] s = new char[plainText.Length + 10];
            for (int i = 0; i < NumberOfCoulmns; i++)
            {
                for (int j = 0; j < NumberOfRows; j++)
                {


                    s[j* NumberOfCoulmns+i] = plainText[(key[i] - 1) , j];

                }
            }


            return new string(s);
        }

        public string Encrypt(string plainText, List<int> key)
        {
            int plainTextlen = plainText.Length;
            int NumberOfCoulmns = key.Count;
            int NumberOfRows = (int)Math.Ceiling((double)plainText.Length / NumberOfCoulmns);
            Char[,] cipherText = new Char[NumberOfRows, NumberOfCoulmns];
            for (int i = 0; i < NumberOfRows; i++)
            {
                for (int j = 0; j < NumberOfCoulmns; j++)
                {
                    if (plainTextlen == 0)
                        break;
                    cipherText[i, j] = plainText[j + i * NumberOfCoulmns];
                    plainTextlen--;
                }
            }
            char[] s = new char[plainText.Length+10];
            for (int i = 0; i < NumberOfCoulmns; i++)
            {
                for (int j = 0; j < NumberOfRows; j++)
                {
                    s[j+ ((key[i] -1 )* NumberOfRows)]= cipherText[j, i];
                    
                }
            }




            return new string(s);
        }
    }
}
