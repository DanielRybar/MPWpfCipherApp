using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CipherApp.Helpers
{
    public static class BruteForce
    {
        // bude ukazovat jak se dá prolomit kupř. heslo a kolik času to zabere (jen demonstrační ukázka)
        // uživatel zadá dva údaje:
        // 1) přeházené znaky
        // 2) délku slova 
        // program vypíše:
        // 1) všechny možnosti (kombinace), které lze ze znaků sestavit
        // 2) počet těchto kombinací
        // 3) čas, jak dlouho to trvalo

        /// <summary>
        /// Zjistí všechny možné kombinace, které lze sestavit ze vstupu chars; volá rekurzivní metodu Permute
        /// </summary>
        /// <param name="chars"></param>
        /// <param name="length"></param>
        /// <returns></returns>
        public static IEnumerable<string> GetPermutations(string chars, int length)
        {
            List<string> permutations = new();
            Permute(chars, length, "", permutations);

            return permutations;
        }

        /// <summary>
        /// Rekurzivně zjistí možné permutace
        /// </summary>
        /// <param name="chars"></param>
        /// <param name="length"></param>
        /// <param name="prefix"></param>
        /// <param name="permutations"></param>
        private static void Permute(string chars, int length, string prefix, List<string> permutations)
        {
            if (length == 0)
            {
                permutations.Add(prefix);
                return;
            }

            foreach (char c in chars)
            {
                Permute(chars, length - 1, prefix + c, permutations);
            }
        }
    }
}
