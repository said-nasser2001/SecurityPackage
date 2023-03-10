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
            throw new NotImplementedException();
        }


        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            int m = (int)Math.Sqrt(key.Count);
            Matrix key_m = new Matrix(key, m, m, Matrix.CONVERSION_TYPE.ROW);
            Matrix cipher_m = new Matrix(cipherText, m, Matrix.DIMS.ROW, Matrix.CONVERSION_TYPE.COLUMNAR);

            int keyDet = key_m.det() % 26 < 0? (key_m.det() % 26) + 26: (key_m.det() % 26);
            int b = bruteB(keyDet);

            Matrix inv_key = key_m.inverse(b); // TODO: fix inverse
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


        private int bruteB(int det)
        {
            for (int i = 1; i <= 26; i++)
            {
                if ((i * det) % 26 == 1)
                    return i;
            }
            return -1;
        }
    }
}
