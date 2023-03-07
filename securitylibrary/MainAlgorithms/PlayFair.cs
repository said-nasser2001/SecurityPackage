using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SecurityLibrary
{

    public class PlayFair : ICryptographic_Technique<string, string>
    {

        // C# is way too fucking smart to allow "return i, j"
        public class Position
        {
            public int row;
            public int col;

            public Position(int x, int y)
            {
                this.row = x;
                this.col = y;
            }
        }


        // this modifies the diffition of % to support negative numbers wraping around
        // such that -1 % 5 = 4, to allow wrap around form negative direction
        private int mod5(int index, int offset)
        {
            index += offset;

            if (index < 0)
                index += 5;
            else
                index %= 5;

            return index;
        }


        private char[][] GenerateKeyMatrix(string key)
        {
            key = RemoveKeyDuplicates(key);
            key = AppendRemainingAlphabet(key);
            char[][] KeyMatrix = FormatIntoMatrix(key);

            return KeyMatrix;
        }

        private string RemoveKeyDuplicates(string key)
        {
            List<bool> freq = new List<bool>(new bool[26]);
            StringBuilder newKey = new StringBuilder();
            for (int i = 0; i < key.Length; i++)
            {
                int index = key[i] - 'a';

                if (!freq[index])
                {
                    newKey.Append(key[i]);
                    freq[index] = true;
                }

            }
            return newKey.ToString();
        }

        private string AppendRemainingAlphabet(string key)
        {
            for (char c = 'a'; c <= 'z'; c++)
            {
                if (key.Contains(c) || c == 'j')
                    continue;
                else
                    key += c;
            }

            if (key.Length != 25)
                throw new Exception("mango");

            return key;
        }

        char[][] FormatIntoMatrix(string key)
        {
            char[][] KeyMatrix = new char[5][];

            for (int i = 0; i < 5; i++)
                KeyMatrix[i] = new char[5];


            int keyIndex = 0;

            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    KeyMatrix[i][j] = key[keyIndex++];
                }
            }

            return KeyMatrix;
        }

        private List<string> FormatText(string text)
        {

            text = text.Replace('j', 'i');
            List<String> textFragments = new List<String>();

            // two pointers to scan text
            int p = 0, q = 1;

            while (p < text.Length)
            {
                StringBuilder textFragment = new StringBuilder();

                // q is out of text bound in the last fragment 
                // condition will apply if number of characters in cipher is odd
                if (q == text.Length)
                {
                    char[] lastFragment = { text[p], 'x' };
                    textFragments.Add(new String(lastFragment));
                    break;
                }

                if (text[p] != text[q])
                {
                    textFragment.Append(text[p]);
                    textFragment.Append(text[q]);

                    p += 2;
                    q += 2;
                }
                else
                {
                    textFragment.Append(text[p]);
                    textFragment.Append('x');

                    p++;
                    q++;
                }

                textFragments.Add(textFragment.ToString());

            }


            return textFragments;

        }

        private Position GetPosition(char c, char[][] KeyMatrix)
        {

            Position position = null;

            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    char currentLetter = KeyMatrix[i][j];
                    if (currentLetter == c)
                    {
                        position = new Position(i, j);
                    }
                }
            }

            return position;
        }



        // Encrypts or Decrypts a substring based on encrypt flag
        private string TransformSubstring(string substring, char[][] KeyMatrix, int encrypt)
        {

            Position firstLetter = GetPosition(substring[0], KeyMatrix);
            Position secondLetter = GetPosition(substring[1], KeyMatrix);

            StringBuilder subcipher = new StringBuilder();

            // same row: get next/prev letters in column, wrap if out of bounds
            if (firstLetter.row == secondLetter.row)
            {
                firstLetter.col = mod5(firstLetter.col, encrypt);
                secondLetter.col = mod5(secondLetter.col, encrypt);

                subcipher.Append(KeyMatrix[firstLetter.row][firstLetter.col]);
                subcipher.Append(KeyMatrix[secondLetter.row][secondLetter.col]);
            }
            // same column: get next/prev letters in row, wrap if out of bounds
            else if (firstLetter.col == secondLetter.col)
            {
                firstLetter.row = mod5(firstLetter.row, encrypt);
                secondLetter.row = mod5(secondLetter.row, encrypt);

                subcipher.Append(KeyMatrix[firstLetter.row][firstLetter.col]);
                subcipher.Append(KeyMatrix[secondLetter.row][secondLetter.col]);
            }
            // the two letters form a diagonal of a rectangle in the matrix
            // replace the letters with letters in the other diagonal (just swap thier columns)
            else
            {
                subcipher.Append(KeyMatrix[firstLetter.row][secondLetter.col]);
                subcipher.Append(KeyMatrix[secondLetter.row][firstLetter.col]);
            }


            return subcipher.ToString();
        }



        public string Encrypt(string plainText, string key)
        {
            plainText = plainText.ToLower();

            char[][] KeyMatrix = GenerateKeyMatrix(key);
            List<string> formattedPlainText = FormatText(plainText);

            StringBuilder cipher = new StringBuilder();

            foreach (var substring in formattedPlainText)
            {
                string subcipher = TransformSubstring(substring, KeyMatrix, 1);
                cipher.Append(subcipher);
            }

            return cipher.ToString();
        }


        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();

            char[][] KeyMatrix = GenerateKeyMatrix(key);
            List<string> formattedCipherText = FormatText(cipherText);


            StringBuilder plain = new StringBuilder();

            foreach (var substring in formattedCipherText)
            {
                string subplain = TransformSubstring(substring, KeyMatrix, -1);
                plain.Append(subplain);
            }


            // remove appended x's
            plain = UndoAppend(plain);

            return plain.ToString();
        }


        private StringBuilder UndoAppend(StringBuilder cipherText)
        {
            for (int i = 1; i < cipherText.Length - 1; i++)
            {
                if (cipherText[i] == 'x' && cipherText[i - 1] == cipherText[i + 1])
                {
                    cipherText.Remove(i, 1);
                    i--; // decrement index after removal to account for shift
                }
            }

            if (cipherText[cipherText.Length - 1] == 'x')
                cipherText.Remove(cipherText.Length - 1, 1);

            return cipherText;
        }
    }
}