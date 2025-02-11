using System;

namespace CipherApp.Helpers
{
    public class Randomizer
    {
        private readonly Random _rand;
        public Randomizer()
        {
            _rand = new Random();
        }

        /// <summary>
        /// Generuje náhodné číslo, vrací zaokrouhlený double pokud je isDecimal true
        /// </summary>
        /// <param name="min"></param>
        /// <param name="max"></param>
        /// <param name="isDecimal"></param>
        /// <returns></returns>
        public object GenerateRandomNumber(int min, int max, bool isDecimal = false)
        {
            if (isDecimal)
                return Math.Round(_rand.NextDouble() * (max - min) + min, 3);

            else
                return _rand.Next(min, max + 1);
        }

        /// <summary>
        /// Generuje řadu náhodných čísel
        /// </summary>
        /// <param name="min"></param>
        /// <param name="max"></param>
        /// <param name="count"></param>
        /// <returns></returns>
        public int[] GenerateRandomRow(int min, int max, int count)
        {
            int[] row = new int[count];
            for (int i = 0; i < count; i++)
            {
                row[i] = (int)GenerateRandomNumber(min, max);
            }
            return row;
        }
    }
}
