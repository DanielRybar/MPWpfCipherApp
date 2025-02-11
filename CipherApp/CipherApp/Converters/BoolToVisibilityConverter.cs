using System;
using System.Globalization;
using System.Windows.Data;

namespace CipherApp.Converters
{
    public class BoolToVisibilityConverter : IValueConverter
    {
        private const string VISIBLE = "Visible";
        private const string HIDDEN = "Hidden";

        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is bool val)
            {
                if (val) return VISIBLE;
                else return HIDDEN;
            }
            return HIDDEN;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
}
