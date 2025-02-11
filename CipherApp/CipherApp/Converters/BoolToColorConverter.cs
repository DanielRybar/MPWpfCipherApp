using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Data;

namespace CipherApp.Converters
{
    public class BoolToColorConverter : IValueConverter
    {
        private const string WHITE = "white";
        private const string COLOR = "#00a0ff";
        
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is bool val)
            {
                return val ? COLOR : WHITE;
            }
            return WHITE;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
}
