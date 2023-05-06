using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;


namespace SecurityLibrary.MD5
{
    public class MD5
    {
        private string message;
        private string A, B, C, D;

        private static uint F(uint b, uint c, uint d) => (b & c) | (~b & d);
        private static uint G(uint b, uint c, uint d) => (b & d) | (c & ~d);
        private static uint H(uint b, uint c, uint d) => b ^ c ^ d;
        private static uint I(uint b, uint c, uint d) => c ^  (b | ~d);

        private Dictionary<int, Func<uint, uint, uint, uint>> logical_functions = new Dictionary<int, Func<uint, uint, uint, uint>>
        {
            {1, F},
            {2, G},
            {3, H},
            {4, I}
        };

        public string GetHash(string text)
        {
            message = convertToBinary(text);

            prepareMessage();
            _ = message.Length % 512 == 0 ? true : throw new Exception("Message not prepared properly");


            initMDBuffers();
 
            // Block processing
                // Single Block
                    // Single step x 16

            throw new NotImplementedException();
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
            A = string.Join("", "01234567".Select(num => Convert.ToString(num - '0', 2).PadLeft(4, '0')));

            B = string.Join("", "89".Select(num => Convert.ToString(num - '0', 2).PadLeft(4, '0'))) +
                string.Join("", "ABCDEF".Select(letter => Convert.ToString(letter - 'A' + 10, 2).PadLeft(4, '0')));

            C = string.Join("", "FEDCBA".Select(letter => Convert.ToString(letter - 'A' + 10, 2).PadLeft(4, '0'))) +
                string.Join("", "98".Select(num => Convert.ToString(num - '0', 2).PadLeft(4, '0')));

            D = string.Join("", "76543210".Select(num => Convert.ToString(num - '0', 2).PadLeft(4, '0')));
        }

        private int computeDWordIndex(int k, int round)
        {
            int index = -1;
            switch (round)
            {
                case 1:
                    index = k;
                    break;

                case 2:
                    index = (1 + 5 * k) % 16;
                    break;
                
                case 3:
                    index = (5 + 3 * k) % 16;
                    break;
                
                case 4:
                    index = (7 * k) % 16;
                    break;

            }

            return index;
        }
    }
}
