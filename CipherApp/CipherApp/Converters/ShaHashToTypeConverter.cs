using CipherApp.Models;
using System;
using System.Globalization;
using System.Windows.Data;

namespace CipherApp.Converters
{
    public class ShaHashToTypeConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is ShaTypes val)
            {
                switch (val)
                {
                    case ShaTypes.SHA1: return "SHA-1 hash";
                    case ShaTypes.SHA256: return "SHA-256 hash";
                    case ShaTypes.SHA384: return "SHA-384 hash";
                    case ShaTypes.SHA512: return "SHA-512 hash";
                    default: return "SHA hash";
                }
            }
            return "SHA hash";
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
}
