using CipherApp.ViewModels;
using Microsoft.Win32;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;

namespace CipherApp.Views
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private const string SWITCH_BLUE = "#5080d8";
        private const string WHITE = "#ffffff";
        private const string BLACK = "#000000";

        private readonly MainViewModel _vm;
        public MainWindow()
        {
            InitializeComponent();
            _vm = (MainViewModel)DataContext;
            _vm.ShowMessage = (text, head) => MessageBox.Show(text, head);
            //_vm.GenerateKeyPairCommand.Execute(null);
            btnPopMenu.Click += (o, s) => popMenu.IsSubmenuOpen = true;

            monoSwitch.IsChecked = true;
            monoSwitch_Checked(new ToggleButton(), new RoutedEventArgs());
            polySwitch.Foreground = GetSCBFromHex(BLACK);
            monoSwitch.Foreground = GetSCBFromHex(BLACK);
            hashSwitch.Foreground = GetSCBFromHex(BLACK); 
            otherSwitch.Foreground = GetSCBFromHex(BLACK);
        }

        private static SolidColorBrush GetSCBFromHex(string hex)
        {
            return (SolidColorBrush)new BrushConverter().ConvertFrom(hex)!;
        }

        private void LoadShaCommand(MenuItem param)
        {
            _vm.ComputeShaFromFileCommand.Execute(param is null || param.CommandParameter == null ? "SHA256" : param.CommandParameter.ToString()!);
        }
        private void LoadMd5Command()
        {
            _vm.ComputeMd5FromFileCommand.Execute(null);
        }
        private void LoadCrc32Command()
        {
            _vm.ComputeCrc32FromFileCommand.Execute(null);
        }
        private void LoadAllHashesCommand()
        {
            _vm.ComputeAllHashesFromFileCommand.Execute(null);
        }

        private void NumberValidationTextBox(object sender, TextCompositionEventArgs e)
        {
            Regex regex = new("[^0-9]+");
            e.Handled = regex.IsMatch(e.Text);
        }

        private void ShaGenerate_Click(object sender, RoutedEventArgs e)
        {
            if (sender is MenuItem param)
            {
                OpenFileDialog fileDialog = new();
                fileDialog.ShowDialog();
                if (fileDialog.FileName.Length > 0)
                {
                    _vm.PathFile = fileDialog.FileName;
                    //BusyIndicator.IsBusy = true;
                    //await Task.Delay(1000);
                    LoadShaCommand(param);
                    //BusyIndicator.IsBusy = false;
                }
            }
        }

        private void Md5Generate_Click(object sender, RoutedEventArgs e)
        {
            if (sender is MenuItem)
            {
                OpenFileDialog fileDialog = new();
                fileDialog.ShowDialog();
                if (fileDialog.FileName.Length > 0)
                {
                    _vm.PathFile = fileDialog.FileName;
                    LoadMd5Command();
                }
            }
        }

        private void Crc32Generate_Click(object sender, RoutedEventArgs e)
        {
            if (sender is MenuItem)
            {
                OpenFileDialog fileDialog = new();
                fileDialog.ShowDialog();
                if (fileDialog.FileName.Length > 0)
                {
                    _vm.PathFile = fileDialog.FileName;
                    LoadCrc32Command();
                }
            }
        }

        private void AllGenerate_Click(object sender, RoutedEventArgs e)
        {
            if (sender is MenuItem)
            {
                OpenFileDialog fileDialog = new();
                fileDialog.ShowDialog();
                if (fileDialog.FileName.Length > 0)
                {
                    _vm.PathFile = fileDialog.FileName;
                    LoadAllHashesCommand();
                }
            }
        }

        private void monoSwitch_Checked(object sender, RoutedEventArgs e)
        {
            if (sender is ToggleButton)
            {
                caesarCard.Visibility = Visibility.Visible;
                augustCard.Visibility = Visibility.Visible;
                atbashCard.Visibility = Visibility.Visible;
                vigenereCard.Visibility = Visibility.Collapsed;
                morseCard.Visibility = Visibility.Collapsed;
                asciiCard.Visibility = Visibility.Collapsed;
                shaCard.Visibility = Visibility.Collapsed;
                md5Card.Visibility = Visibility.Collapsed;
                rsaCard.Visibility = Visibility.Collapsed;
                rngCard.Visibility = Visibility.Collapsed;
                bruteforceCard.Visibility = Visibility.Collapsed;

                polySwitch.IsEnabled = true;
                monoSwitch.IsEnabled = false;
                hashSwitch.IsEnabled = true;
                otherSwitch.IsEnabled = true;

                polySwitch.Background = GetSCBFromHex(WHITE);
                monoSwitch.Background = GetSCBFromHex(SWITCH_BLUE);
                hashSwitch.Background = GetSCBFromHex(WHITE);
                otherSwitch.Background = GetSCBFromHex(WHITE);

                polySwitch.IsChecked = false;
                hashSwitch.IsChecked = false;
                otherSwitch.IsChecked = false;

                _vm.SelectedIndex = 0;
            }
        }

        private void polySwitch_Checked(object sender, RoutedEventArgs e)
        {
            if (sender is ToggleButton)
            {
                caesarCard.Visibility = Visibility.Collapsed;
                augustCard.Visibility = Visibility.Collapsed;
                atbashCard.Visibility = Visibility.Collapsed;
                vigenereCard.Visibility = Visibility.Visible;
                morseCard.Visibility = Visibility.Collapsed;
                asciiCard.Visibility = Visibility.Collapsed;
                shaCard.Visibility = Visibility.Collapsed;
                md5Card.Visibility = Visibility.Collapsed;
                rsaCard.Visibility = Visibility.Collapsed;
                rngCard.Visibility = Visibility.Collapsed;
                bruteforceCard.Visibility = Visibility.Collapsed;

                polySwitch.IsEnabled = false;
                monoSwitch.IsEnabled = true;
                hashSwitch.IsEnabled = true;
                otherSwitch.IsEnabled = true;

                polySwitch.Background = GetSCBFromHex(SWITCH_BLUE);
                monoSwitch.Background = GetSCBFromHex(WHITE);
                hashSwitch.Background = GetSCBFromHex(WHITE);
                otherSwitch.Background = GetSCBFromHex(WHITE);

                monoSwitch.IsChecked = false;
                hashSwitch.IsChecked = false;
                otherSwitch.IsChecked = false;

                _vm.SelectedIndex = 3;
            }
        }

        private void hashSwitch_Checked(object sender, RoutedEventArgs e)
        {
            if (sender is ToggleButton)
            {
                caesarCard.Visibility = Visibility.Collapsed;
                augustCard.Visibility = Visibility.Collapsed;
                atbashCard.Visibility = Visibility.Collapsed;
                vigenereCard.Visibility = Visibility.Collapsed;
                morseCard.Visibility = Visibility.Collapsed;
                asciiCard.Visibility = Visibility.Collapsed;
                shaCard.Visibility = Visibility.Visible;
                md5Card.Visibility = Visibility.Visible;
                rsaCard.Visibility = Visibility.Collapsed;
                rngCard.Visibility = Visibility.Collapsed;
                bruteforceCard.Visibility = Visibility.Collapsed;

                polySwitch.IsEnabled = true;
                monoSwitch.IsEnabled = true;
                hashSwitch.IsEnabled = false;
                otherSwitch.IsEnabled = true;

                polySwitch.Background = GetSCBFromHex(WHITE);
                monoSwitch.Background = GetSCBFromHex(WHITE);
                hashSwitch.Background = GetSCBFromHex(SWITCH_BLUE);
                otherSwitch.Background = GetSCBFromHex(WHITE);

                monoSwitch.IsChecked = false;
                polySwitch.IsChecked = false;
                otherSwitch.IsChecked = false;

                _vm.SelectedIndex = 6;
            }
        }

        private void otherSwitch_Checked(object sender, RoutedEventArgs e)
        {
            if (sender is ToggleButton)
            {
                caesarCard.Visibility = Visibility.Collapsed;
                augustCard.Visibility = Visibility.Collapsed;
                atbashCard.Visibility = Visibility.Collapsed;
                vigenereCard.Visibility = Visibility.Collapsed;
                morseCard.Visibility = Visibility.Visible;
                asciiCard.Visibility = Visibility.Visible;
                shaCard.Visibility = Visibility.Collapsed;
                md5Card.Visibility = Visibility.Collapsed;
                rsaCard.Visibility = Visibility.Visible;
                rngCard.Visibility = Visibility.Visible;
                bruteforceCard.Visibility = Visibility.Visible;

                polySwitch.IsEnabled = true;
                monoSwitch.IsEnabled = true;
                hashSwitch.IsEnabled = true;
                otherSwitch.IsEnabled = false;

                polySwitch.Background = GetSCBFromHex(WHITE);
                monoSwitch.Background = GetSCBFromHex(WHITE);
                hashSwitch.Background = GetSCBFromHex(WHITE);
                otherSwitch.Background = GetSCBFromHex(SWITCH_BLUE);

                monoSwitch.IsChecked = false;
                polySwitch.IsChecked = false;
                hashSwitch.IsChecked = false;

                _vm.SelectedIndex = 4;
            }
        }
    }
}