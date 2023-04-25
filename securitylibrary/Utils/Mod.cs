using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{

    public class Mod
    {
        // performs x^y % mod
        static public long Pow(long x, long y, long mod)
        {
            long ans = 1;
            for(int i = 0; i < y; i++)
            {
                ans = ((ans % mod) * (x % mod)) % mod;
            }
            return ans;
        }

        static public int Pow(int x, int y, int mod)
        {
            int ans = 1;
            for (int i = 0; i < y; i++)
            {
                ans = ((ans % mod) * (x % mod)) % mod;
            }
            return ans;
        }

    }
}
