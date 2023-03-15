using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher :  ICryptographicTechnique<List<int>, List<int>>
    {
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            int m = 2;
            Matrix plain_m = new Matrix(plainText, m, m, Matrix.CONVERSION_TYPE.COLUMNAR);
            Matrix cipher_m = new Matrix(cipherText, m, m, Matrix.CONVERSION_TYPE.COLUMNAR);


            Matrix key = brute2x2Key(plain_m, cipher_m);
            return key.to1D(Matrix.CONVERSION_TYPE.ROW);
        }

        
        private Matrix brute2x2Key(Matrix plain, Matrix cipher)
        {
            Matrix key = new Matrix(2, 2);
            for (int i1 = 0; i1 < 26; i1++)
            {
                for (int i2 = 0; i2 < 26; i2++)
                {
                    for (int i3 = 0; i3 < 26; i3++)
                    {
                        for (int i4 = 0; i4 < 26; i4++)
                        {
                            key[0, 0] = i1;
                            key[0, 1] = i2;
                            key[1, 0] = i3;
                            key[1, 1] = i4;

                            if (Encrypt(plain, key) == cipher)
                                return key;
                        }
                    }
                }
            }

            throw new SecurityLibrary.InvalidAnlysisException();
        }


        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            int m = (int)Math.Sqrt(key.Count);
            Matrix key_m = new Matrix(key, m, m, Matrix.CONVERSION_TYPE.ROW);
            Matrix cipher_m = new Matrix(cipherText, m, Matrix.DIMS.ROW, Matrix.CONVERSION_TYPE.COLUMNAR);

            if (!verifyInverseKeyExists(key_m))
                throw new Exception("Cipher can't be decrypted, key doesn't exist");

            int keyDet = key_m.det() % 26 < 0? (key_m.det() % 26) + 26: (key_m.det() % 26);
            int b = bruteB(keyDet);

            Matrix inv_key = key_m.inverse(b, 26); // TODO: fix inverse
            
            if (key_m.getShape()[0] == 3)
                inv_key = Matrix.T(inv_key);

            Matrix res = inv_key.mul(cipher_m);

            return res.to1D(Matrix.CONVERSION_TYPE.COLUMNAR);
        }

        
        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            int m = (int)Math.Sqrt(key.Count);

            Matrix key_m = new Matrix(key, m, m, Matrix.CONVERSION_TYPE.ROW);
            Matrix plainText_m = new Matrix(plainText, m, Matrix.DIMS.ROW, Matrix.CONVERSION_TYPE.COLUMNAR);

            Matrix res = key_m.mul(plainText_m);

            return res.to1D(Matrix.CONVERSION_TYPE.COLUMNAR);
        }

        public Matrix Encrypt(Matrix plainText, Matrix key)
        {
            Matrix res = key.mul(plainText);
            return res;
        }


        public List<int> Analyse3By3Key(List<int> plainText, List<int> cipherText)
        {
            int m = 3;
            Matrix plain_m = new Matrix(plainText, m, m, Matrix.CONVERSION_TYPE.ROW);
            Matrix cipher_m = new Matrix(cipherText, m, m, Matrix.CONVERSION_TYPE.COLUMNAR);


            int det = plain_m.det() % 26;
            int b = bruteB(det);

            Matrix key = cipher_m.mul(plain_m.inverse(b, 26));
            return key.to1D(Matrix.CONVERSION_TYPE.ROW);
        }


        private bool verifyInverseKeyExists(Matrix key)
        {
            // All elements are nonnegative and less than 26
            for (int i = 0; i < key.getShape()[0]; i++)
            {
                for (int j = 0; j < key.getShape()[1]; j++)
                    if (key[i, j] < 0 || key[i, j] > 25) return false;
            }


            // Determinant not equal 0
            int det = key.det() % 26 < 0 ? (key.det() % 26) + 26 : (key.det() % 26);
            if (det == 0)
                return false;


            // No common factors between det(k) and 26(GCD(26, det(k)) = 1
            if (GCD(det, 26) > 1)
                return false;


            // There is exists a positive integer b<26 and 
            //(b X det(k)) mod 26 = 1, b is called  multiplicative inverse of det(k
            int b = bruteB(det);
            if (key.getShape()[1] == 3 && b == -1)
                return false;

            return true;

        }

        private int bruteB(int det)
        {
            for (int i = 1; i <= 26; i++)
            {
                if ((i * det) % 26 == 1)
                    return i;
            }
            return -1;
        }
        private int GCD(int a, int b)
        {
            return b == 0 ? a : GCD(b, a % b);
        }
    }
}
