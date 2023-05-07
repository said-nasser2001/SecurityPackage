﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;


namespace SecurityLibrary.MD5
{
    public class MD5
    {

        private string message;
        private uint A, B, C, D;
        uint[] DWord = new uint[64];
        uint[] T = new uint[64];

        int[] shiftValues = new int[64] {
            7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
            5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
            4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
            6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
        };
        private static readonly uint[] S = {
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
        0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
        0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
        0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
        0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
    };



        private static uint F(uint b, uint c, uint d) => (b & c) | (~b & d);
        private static uint G(uint b, uint c, uint d) => (b & d) | (c & ~d);
        private static uint H(uint b, uint c, uint d) => b ^ c ^ d;
        private static uint I(uint b, uint c, uint d) => c ^ (b | ~d);

        private Dictionary<int, Func<uint, uint, uint, uint>> logical_functions = new Dictionary<int, Func<uint, uint, uint, uint>>
        {
            {0, F},
            {1, G},
            {2, H},
            {3, I}
        };

        public string GetHash(string text)
        {
            message = convertToBinary(text);

            prepareMessage();
            _ = message.Length % 512 == 0 ? true : throw new Exception("Message not prepared properly");
            Console.WriteLine(message);

            initMDBuffers();
            generateDWord();
            generate_T_table();
            int NumberOfBlocks = message.Length / 512;
            for (int i = 0; i < NumberOfBlocks; i++)
            {
                uint[] chunk = new uint[16];
                for (int j = 0; j < 16; j++)
                    chunk[j] = Convert.ToUInt32(message.Substring(32 * j, 32), 2);

                uint a = A;
                uint b = B;
                uint c = C;
                uint d = D;
                uint f = 0;
                uint g = 0;

                for (int k = 0; k < 4; k++)
                {
                    for (int l = 0; l < 16; l++)
                    {
                        f = logical_functions[k].Invoke(b, c, d);
                        g = (uint)computeDWordIndex(k, l);
                        uint tmp = d;
                        d = c;
                        c = b;
                        b = b + leftRotate((a + f + S[k*16+l] + chunk[g]), shiftValues[k * 16 + l]);
                        a = tmp;
                        string Da = a.ToString("X");
                        string Db = b.ToString("X");
                        string Dc = c.ToString("X");
                        string Dd = d.ToString("X");
                    }
                }
                A += a;
                B += b;
                C += c;
                D += d;
            }

            string x = GetByteString(A) + GetByteString(B) + GetByteString(C) + GetByteString(D);
            return x;

        }
        private static string GetByteString(uint x)
        {
            byte[] bytes = BitConverter.GetBytes(x);
            Array.Reverse(bytes); // Reverse the byte order
            return BitConverter.ToString(bytes).Replace("-", "").ToLower();
        }



        // Return concatenated 8 bit represenation of each letter
        private string convertToBinary(string text)
        {
            byte[] bytes = Encoding.ASCII.GetBytes(text);
            string binary = string.Join("", bytes.Select(byt => Convert.ToString(byt, 2).PadLeft(8, '0')));
            return binary;
        }

        private void prepareMessage()
        {
            int originalLength = message.Length;
            int targetLength = getTargetLength(originalLength);
            message += "1";
            message = message.PadRight(targetLength, '0');
            string binaryMessageLength = Convert.ToString(originalLength, 2).PadLeft(64, '0');
            message += binaryMessageLength;
        }

        private int getTargetLength(int binaryLength)
        {
            int mod = binaryLength % 512;
            return mod > 448 ? (binaryLength + mod + 448) : binaryLength + (448 - mod);
        }

        private void initMDBuffers()
        {
            A = Convert.ToUInt32(string.Join("", "01234567".Select(num => Convert.ToString(num - '0', 2).PadLeft(4, '0'))), 2);

            B = Convert.ToUInt32(string.Join("", "89".Select(num => Convert.ToString(num - '0', 2).PadLeft(4, '0'))) +
                string.Join("", "ABCDEF".Select(letter => Convert.ToString(letter - 'A' + 10, 2).PadLeft(4, '0'))), 2);

            C = Convert.ToUInt32(string.Join("", "FEDCBA".Select(letter => Convert.ToString(letter - 'A' + 10, 2).PadLeft(4, '0'))) +
                string.Join("", "98".Select(num => Convert.ToString(num - '0', 2).PadLeft(4, '0'))), 2);

            D = Convert.ToUInt32(string.Join("", "76543210".Select(num => Convert.ToString(num - '0', 2).PadLeft(4, '0'))), 2);
        }

        private void generate_T_table()
        {
            for (int i = 0; i < message.Length / 32; i++)
            {

                T[i] = (uint)((1L << 32) * DWord[i] * Math.Abs(Math.Sin(i + 1)));
                string x = T[i].ToString("X");
            }
        }

        private void generateDWord()
        {
            string temp;

            for (int i = 0; i < message.Length / 32; i++)
            {
                temp = "";
                for (int j = i * 32; j < ((i + 1) * 32) && j < message.Length; j++)
                {
                    temp += message[j].ToString();
                }

                DWord[i] = Convert.ToUInt32(temp, 2);
            }
        }

        private int computeDWordIndex(int k, int l)
        {
            int index = -1;
            switch (k)
            {
                case 0:
                    index = l;
                    break;

                case 1:
                    index = (1 + 5 * l) % 16;
                    break;

                case 2:
                    index = (5 + 3 * l) % 16;
                    break;

                case 3:
                    index = (7 * l) % 16;
                    break;

            }

            return index;
        }
        private uint leftRotate(uint x, int s)
        {
            return (x << s) | (x >> (32 - s));
        }

    }
}
