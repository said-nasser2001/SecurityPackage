using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SecurityLibrary.AES;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        ExtendedEuclid ExtendedEuclid = new ExtendedEuclid();
        public int Encrypt(int p, int q, int M, int e)
        {
            int n = p * q;
            return (int)Mod.Pow(M, e, n);
        }

        public int Decrypt(int p, int q, int C, int e)
        {
            int n = p * q;
            int phi = (p - 1) * (q - 1);
            int d = ExtendedEuclid.GetMultiplicativeInverse(e, phi);
            return (int)Mod.Pow(C, d, n);
        }
    }
}
