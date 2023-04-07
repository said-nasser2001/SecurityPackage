using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {
        #region givenMatrices
        public string[,] RC = new string[4, 10] { { "01" , "02" , "04" , "08" , "10" , "20" , "40" , "80" , "1b" , "36" },
                                                  { "00" , "00" , "00" , "00" , "00" , "00" , "00" , "00" , "00" , "00" },
                                                  { "00" , "00" , "00" , "00" , "00" , "00" , "00" , "00" , "00" , "00" },
                                                  { "00" , "00" , "00" , "00" , "00" , "00" , "00" , "00" , "00" , "00" } };

        public string[,] SBox = new string[16, 16] { { "63", "7C", "77", "7B", "F2", "6B", "6F", "C5", "30", "01", "67", "2B", "FE", "D7", "AB", "76" },
                                                     { "CA", "82", "C9", "7D", "FA", "59", "47", "F0", "AD", "D4", "A2", "AF", "9C", "A4", "72", "C0" },
                                                     { "B7", "FD", "93", "26", "36", "3F", "F7", "CC", "34", "A5", "E5", "F1", "71", "D8", "31", "15" },
                                                     { "04", "C7", "23", "C3", "18", "96", "05", "9A", "07", "12", "80", "E2", "EB", "27", "B2", "75" },
                                                     { "09", "83", "2C", "1A", "1B", "6E", "5A", "A0", "52", "3B", "D6", "B3", "29", "E3", "2F", "84" },
                                                     { "53", "D1", "00", "ED", "20", "FC", "B1", "5B", "6A", "CB", "BE", "39", "4A", "4C", "58", "CF" },
                                                     { "D0", "EF", "AA", "FB", "43", "4D", "33", "85", "45", "F9", "02", "7F", "50", "3C", "9F", "A8" },
                                                     { "51", "A3", "40", "8F", "92", "9D", "38", "F5", "BC", "B6", "DA", "21", "10", "FF", "F3", "D2" },
                                                     { "CD", "0C", "13", "EC", "5F", "97", "44", "17", "C4", "A7", "7E", "3D", "64", "5D", "19", "73" },
                                                     { "60", "81", "4F", "DC", "22", "2A", "90", "88", "46", "EE", "B8", "14", "DE", "5E", "0B", "DB" },
                                                     { "E0", "32", "3A", "0A", "49", "06", "24", "5C", "C2", "D3", "AC", "62", "91", "95", "E4", "79" },
                                                     { "E7", "C8", "37", "6D", "8D", "D5", "4E", "A9", "6C", "56", "F4", "EA", "65", "7A", "AE", "08" },
                                                     { "BA", "78", "25", "2E", "1C", "A6", "B4", "C6", "E8", "DD", "74", "1F", "4B", "BD", "8B", "8A" },
                                                     { "70", "3E", "B5", "66", "48", "03", "F6", "0E", "61", "35", "57", "B9", "86", "C1", "1D", "9E" },
                                                     { "E1", "F8", "98", "11", "69", "D9", "8E", "94", "9B", "1E", "87", "E9", "CE", "55", "28", "DF" },
                                                     { "8C", "A1", "89", "0D", "BF", "E6", "42", "68", "41", "99", "2D", "0F", "B0", "54", "BB", "16" } };
        

        public string[,] mixColumnsMat = new string[4,4] { { "02", "03", "01", "01" },
                                                           { "01", "02", "03", "01" },
                                                           { "01", "01", "02", "03" },
                                                           { "03", "01", "01", "02" } };

        public string[,] invMixColumnsMat = new string[4,4]  { { "0E", "0B", "0D", "09" },
                                                               { "09", "0E", "0B", "0D" },
                                                               { "0D", "09", "0E", "0B" },
                                                               { "0B", "0D", "09", "0E" } };
        #endregion

        public override string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }

        public override string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();
            string[,] m = convertToMatrix(plainText);
            string[,] sb = subBytes(m);
            return "";
        }

        private string[,] subBytes(string[,] state)
        {
            string[,] resultMatrix = new string[4, 4];
            string temp = "";
            int sBoxRowIndex, sBoxColIndex;
            string hexNumbers = "0123456789abcdef";

            for (int row = 0; row < 4; row++)
            {
                for(int col = 0; col < 4; col++)
                {
                    temp = state[row, col];
                    sBoxRowIndex = hexNumbers.IndexOf(temp[0]);
                    sBoxColIndex = hexNumbers.IndexOf(temp[1]);
                    resultMatrix[row, col] = SBox[sBoxRowIndex, sBoxColIndex];
                }
            }


            return resultMatrix;
        }

        private string[,] shiftRows(string[,] state)
        {
            throw new NotImplementedException();
        }

        private string[,] mixColumns(string[,] state)
        {
            throw new NotImplementedException();
        }

        private string[,] addRoundKey(string[,] state, string[,] roundKey)
        {
            throw new NotImplementedException();
        }

        private string[,] keySchedule(string[,] currentKey, int round_no)
        {
            throw new NotImplementedException();
        }

        private string[,] invSubBytes(string[,] state)
        {
            throw new NotImplementedException();
        }

        private string[,] invShiftRows(string[,] state)
        {
            throw new NotImplementedException();
        }

        private string[,] invMixColumns(string[,] state)
        {
            throw new NotImplementedException();
        }

        private string applyXOR(string s1, string s2)
        {
            throw new NotImplementedException();
        }

        private string[,] convertToMatrix(string text)
        {
            string[,] matrix = new string[4, 4];
            int row = 0, col = 0;

            for (int char_no = 2; char_no < text.Length; char_no+=2)
            {
                if(col == 4)
                {
                    col = 0;
                    row++;
                }

                if(row == 4)
                {
                    break;
                }

                if (char_no == text.Length - 1)
                {
                    matrix[row, col] = "" + text[char_no];
                }
                else
                {
                    matrix[row, col] = "" + text[char_no] + text[char_no + 1];
                }

                col++;
                    
            }

            if (matrix[3, 3].Length == 1)
            {
                matrix[3, 3] = "0" + text[text.Length - 1];
            }



            return matrix;
        }

        private string convertToString(string[,] matrix)
        {
            string text = "";

            for (int row = 0; row < 4; row++)
            {
                for (int col = 0; col < 4; col++)
                {
                    text += matrix[row, col];
                }
            }


            return text;
        }

        
    }
}
