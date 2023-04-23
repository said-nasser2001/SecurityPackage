using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SecurityLibrary.AES;

namespace SecurityLibrary.ElGamal
{
    public class ElGamal
    {
        /// <summary>
        /// Encryption
        /// </summary>
        /// <param name="alpha"></param>
        /// <param name="q"></param>
        /// <param name="y"></param>
        /// <param name="k"></param>
        /// <returns>list[0] = C1, List[1] = C2</returns>
        public List<long> Encrypt(int q, int alpha, int y, int k, int m)
        {
            List<long> ans = new List<long>();
            long c1 = Mod.Pow(alpha, k, q);
            ans.Add(c1);

            long K = Mod.Pow(y, k, q);
            long c2 = (K * m) % q;
            ans.Add(c2);

            return ans;

        }
        public int Decrypt(int c1, int c2, int x, int q)
        {
            int K = (int) Mod.Pow(c1, x, q);

            ExtendedEuclid euclid = new ExtendedEuclid();
            int K_1 = euclid.GetMultiplicativeInverse(K, q);

            return (K_1 * c2) % q;

        }
    }
}
