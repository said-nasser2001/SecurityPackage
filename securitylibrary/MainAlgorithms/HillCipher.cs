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


            int det = plain_m.det() %  26;
            int b = bruteB(det);

            Matrix key = cipher_m.mul(hill_2x2_inverse(plain_m));
            return key.to1D(Matrix.CONVERSION_TYPE.ROW);
        }

        private Matrix hill_2x2_inverse(Matrix m)
        {
            int det = m.det() % 26;
            int b = bruteB(det);
            int mod = 26;

            Matrix res = new Matrix(2, 2);


            res[0, 0] = (b * m[1, 1]) % mod < 0 ? (b * m[1, 1] ) % mod + mod : (m[1, 1] * b) % mod; // TODO: call garbage management
            res[1, 1] = (m[0, 0] * b) % mod < 0 ? (m[0, 0] * b) % mod + mod : (m[0, 0] * b) % mod; // TODO: call garbage management

            res[0, 1] = (m[0, 1] * -1 * b) % mod < 0 ? (m[0, 1] * -1 * b) % mod + mod : (m[0, 1] * -1 * b) % mod; // TODO: call garbage management
            res[1, 0] = (m[1, 0] * -1 * b) % mod < 0 ? (m[1, 0] * -1 * b) % mod + mod : (m[1, 0] * -1 * b) % mod;// TODO: call garbage management

            return res;
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


        public List<int> Analyse3By3Key(List<int> plainText, List<int> cipherText)
        {
            throw new NotImplementedException();
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
