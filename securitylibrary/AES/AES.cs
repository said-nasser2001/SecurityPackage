﻿using System;
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
        

        public string[,] invMixColumnsMat = new string[4,4]  { { "0E", "0B", "0D", "09" },
                                                               { "09", "0E", "0B", "0D" },
                                                               { "0D", "09", "0E", "0B" },
                                                               { "0B", "0D", "09", "0E" } };
        int[] MultiplyByTwoLookUpTable = {0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e, 0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e,
                                            0x20, 0x22, 0x24, 0x26, 0x28, 0x2a, 0x2c, 0x2e, 0x30, 0x32, 0x34, 0x36, 0x38, 0x3a, 0x3c, 0x3e,
                                            0x40, 0x42, 0x44, 0x46, 0x48, 0x4a, 0x4c, 0x4e, 0x50, 0x52, 0x54, 0x56, 0x58, 0x5a, 0x5c, 0x5e,
                                            0x60, 0x62, 0x64, 0x66, 0x68, 0x6a, 0x6c, 0x6e, 0x70, 0x72, 0x74, 0x76, 0x78, 0x7a, 0x7c, 0x7e,
                                            0x80, 0x82, 0x84, 0x86, 0x88, 0x8a, 0x8c, 0x8e, 0x90, 0x92, 0x94, 0x96, 0x98, 0x9a, 0x9c, 0x9e,
                                            0xa0, 0xa2, 0xa4, 0xa6, 0xa8, 0xaa, 0xac, 0xae, 0xb0, 0xb2, 0xb4, 0xb6, 0xb8, 0xba, 0xbc, 0xbe,
                                            0xc0, 0xc2, 0xc4, 0xc6, 0xc8, 0xca, 0xcc, 0xce, 0xd0, 0xd2, 0xd4, 0xd6, 0xd8, 0xda, 0xdc, 0xde,
                                            0xe0, 0xe2, 0xe4, 0xe6, 0xe8, 0xea, 0xec, 0xee, 0xf0, 0xf2, 0xf4, 0xf6, 0xf8, 0xfa, 0xfc, 0xfe,
                                            0x1b, 0x19, 0x1f, 0x1d, 0x13, 0x11, 0x17, 0x15, 0x0b, 0x09, 0x0f, 0x0d, 0x03, 0x01, 0x07, 0x05,
                                            0x3b, 0x39, 0x3f, 0x3d, 0x33, 0x31, 0x37, 0x35, 0x2b, 0x29, 0x2f, 0x2d, 0x23, 0x21, 0x27, 0x25,
                                            0x5b, 0x59, 0x5f, 0x5d, 0x53, 0x51, 0x57, 0x55, 0x4b, 0x49, 0x4f, 0x4d, 0x43, 0x41, 0x47, 0x45,
                                            0x7b, 0x79, 0x7f, 0x7d, 0x73, 0x71, 0x77, 0x75, 0x6b, 0x69, 0x6f, 0x6d, 0x63, 0x61, 0x67, 0x65,
                                            0x9b, 0x99, 0x9f, 0x9d, 0x93, 0x91, 0x97, 0x95, 0x8b, 0x89, 0x8f, 0x8d, 0x83, 0x81, 0x87, 0x85,
                                            0xbb, 0xb9, 0xbf, 0xbd, 0xb3, 0xb1, 0xb7, 0xb5, 0xab, 0xa9, 0xaf, 0xad, 0xa3, 0xa1, 0xa7, 0xa5,
                                            0xdb, 0xd9, 0xdf, 0xdd, 0xd3, 0xd1, 0xd7, 0xd5, 0xcb, 0xc9, 0xcf, 0xcd, 0xc3, 0xc1, 0xc7, 0xc5,
                                            0xfb, 0xf9, 0xff, 0xfd, 0xf3, 0xf1, 0xf7, 0xf5, 0xeb, 0xe9, 0xef, 0xed, 0xe3, 0xe1, 0xe7, 0xe5 };

        int[] MultiplyByThreeLookUpTable = {0x00,0x03,0x06,0x05,0x0c,0x0f,0x0a,0x09,0x18,0x1b,0x1e,0x1d,0x14,0x17,0x12,0x11,
                                            0x30,0x33,0x36,0x35,0x3c,0x3f,0x3a,0x39,0x28,0x2b,0x2e,0x2d,0x24,0x27,0x22,0x21,
                                            0x60,0x63,0x66,0x65,0x6c,0x6f,0x6a,0x69,0x78,0x7b,0x7e,0x7d,0x74,0x77,0x72,0x71,
                                            0x50,0x53,0x56,0x55,0x5c,0x5f,0x5a,0x59,0x48,0x4b,0x4e,0x4d,0x44,0x47,0x42,0x41,
                                            0xc0,0xc3,0xc6,0xc5,0xcc,0xcf,0xca,0xc9,0xd8,0xdb,0xde,0xdd,0xd4,0xd7,0xd2,0xd1,
                                            0xf0,0xf3,0xf6,0xf5,0xfc,0xff,0xfa,0xf9,0xe8,0xeb,0xee,0xed,0xe4,0xe7,0xe2,0xe1,
                                            0xa0,0xa3,0xa6,0xa5,0xac,0xaf,0xaa,0xa9,0xb8,0xbb,0xbe,0xbd,0xb4,0xb7,0xb2,0xb1,
                                            0x90,0x93,0x96,0x95,0x9c,0x9f,0x9a,0x99,0x88,0x8b,0x8e,0x8d,0x84,0x87,0x82,0x81,
                                            0x9b,0x98,0x9d,0x9e,0x97,0x94,0x91,0x92,0x83,0x80,0x85,0x86,0x8f,0x8c,0x89,0x8a,
                                            0xab,0xa8,0xad,0xae,0xa7,0xa4,0xa1,0xa2,0xb3,0xb0,0xb5,0xb6,0xbf,0xbc,0xb9,0xba,
                                            0xfb,0xf8,0xfd,0xfe,0xf7,0xf4,0xf1,0xf2,0xe3,0xe0,0xe5,0xe6,0xef,0xec,0xe9,0xea,
                                            0xcb,0xc8,0xcd,0xce,0xc7,0xc4,0xc1,0xc2,0xd3,0xd0,0xd5,0xd6,0xdf,0xdc,0xd9,0xda,
                                            0x5b,0x58,0x5d,0x5e,0x57,0x54,0x51,0x52,0x43,0x40,0x45,0x46,0x4f,0x4c,0x49,0x4a,
                                            0x6b,0x68,0x6d,0x6e,0x67,0x64,0x61,0x62,0x73,0x70,0x75,0x76,0x7f,0x7c,0x79,0x7a,
                                            0x3b,0x38,0x3d,0x3e,0x37,0x34,0x31,0x32,0x23,0x20,0x25,0x26,0x2f,0x2c,0x29,0x2a,
                                            0x0b,0x08,0x0d,0x0e,0x07,0x04,0x01,0x02,0x13,0x10,0x15,0x16,0x1f,0x1c,0x19,0x1a};


        int[,] mixColumnsMat = new int[4, 4] { { 0x02, 0x03,0x01, 0x01 },
                                                           { 0x01, 0x02,  0x03, 0x01 },
                                                           { 0x01, 0x01, 0x02,  0x03 },
                                                           {  0x03, 0x01, 0x01, 0x02 } };
        #endregion

        public override string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }

        public override string Encrypt(string plainText, string key)
        {
            throw new NotImplementedException();
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
            string[,] resultMatrix = new string[4,4];
            int rotateBy;

            for (int row = 0; row < 4; row++)
            {
                rotateBy = row;

               for (int col = 0; col < 4; col++)
               {
                 resultMatrix[row, col] = state[row, (col + rotateBy) % 4];
               }    
                
            }


            return resultMatrix;
        }

        public string[,] mixColumns(string[,] state)
        {
            string[,] res = new string[4, 4];
            for (int row = 0; row < 4; row++)
            {
                for (int col = 0; col < 4; col++)
                {
                    res[row, col] = VectorGaloisFieldMul(mixColumnsMat, row, state, col);
                }
            }
            return res;
        }
        private string VectorGaloisFieldMul(int[,] data1, int targetRow, string[,] state, int targetCol)
        {

            int sum = 0;
            int res = 0;
            for (int i = 0; i < 4; i++)
            {
                switch (data1[targetRow, i])
                {
                    case 0x01:
                        res = Convert.ToInt32(state[i, targetCol], 16);
                        break;
                    case 0x02:
                        res = MultiplyByTwoLookUpTable[Convert.ToInt32(state[i, targetCol], 16)];
                        break;
                    case 0x03:
                        res = MultiplyByThreeLookUpTable[Convert.ToInt32(state[i, targetCol], 16)];
                        break;
                }
                if (i == 0)
                    sum = res;
                else
                    sum ^= res;
            }

            return sum.ToString("X2");
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
