using System;
using System.Globalization;
using System.Windows.Data;

namespace CipherApp.Converters
{
    public class BoolToModeConverter : IMultiValueConverter
    {
        const string CAESAR = "Caesarova šifra";
        const string AUGUST = "Augustova šifra";
        const string ATBASH = "Atbash";
        const string VIGENERE = "Vigenèrova šifra";
        const string MORSE = "Morseovka";
        const string ASCII = "ASCII kód";
        const string SHA = "SHA hash";
        const string MD5 = "MD5 hash";
        const string RSA = "RSA";
        const string DEFAULT = "Šifra";

        public object Convert(object[] values, Type targetType, object parameter, CultureInfo culture)
        {
            if ((values != null) && (values[0] is bool mode) && (values[1] is int index))
            {
                switch (index)
                {
                    case 0: return mode ? CAESAR + " - dekodér" : CAESAR + " - enkodér"; // dekodér - odšifruje; enkodér - zašifruje
                    case 1: return mode ? AUGUST + " - dekodér" : AUGUST + " - enkodér";
                    case 2: return mode ? ATBASH + " - dekodér" : ATBASH + " - enkodér";
                    case 3: return mode ? VIGENERE + " - dekodér" : VIGENERE + " - enkodér";
                    case 4: return mode ? MORSE + " - dekodér" : MORSE + " - enkodér";
                    case 5: return mode ? ASCII + " - dekodér" : ASCII + " - enkodér";
                    case 6: return SHA;
                    case 7: return MD5;
                    case 8: return mode ? RSA + " - dekodér (dešifruje se podle SK)" : RSA + " - enkodér (šifruje se podle VK)";
                    default: return DEFAULT;
                }
            }
            return DEFAULT;
        }

        public object[] ConvertBack(object value, Type[] targetTypes, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
}
