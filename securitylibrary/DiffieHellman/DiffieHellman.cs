using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman 
    {
        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            List<int> keys = new List<int>();

            // User A Generates and sends y_a to User B from private xa
            int ya = Mod.Pow(alpha, xa, q);

            // User B Generates and sends y_b to user A from private xb
            int yb = Mod.Pow(alpha, xb, q);

            // User A Generates key from y_b and private xa
            int key_a = Mod.Pow(yb, xa, q);
            keys.Add(key_a);

            // User B Generates key from y_a and private xb
            int key_b = Mod.Pow(ya, xb, q);
            keys.Add(key_b);

            return keys;

        }
    }
}
