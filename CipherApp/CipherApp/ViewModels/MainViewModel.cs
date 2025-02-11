using CipherApp.Helpers;
using CipherApp.Models;
using CipherApp.ViewModels.Commands;
using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing.Configuration;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Threading;
using Path = System.IO.Path;

namespace CipherApp.ViewModels
{
    public class MainViewModel : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler? PropertyChanged;
        public void NotifyPropertyChanged(string propertyName = "")
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }

        /// <summary>
        /// Podprogram pro interakci vstupu s výstupem a použití správné šifrovací funkce
        /// DECODE = ODŠIFROVAT; ENCODE = ZAŠIFROVAT
        /// </summary>
        /// <param name="input"></param>
        /// <param name="output"></param>
        /// <param name="mode"></param>
        /// <param name="isBackwardsOrSep"></param>
        /// <param name="type"></param>
        /// <param name="shift"></param>
        /// <param name="key"></param>
        /// <param name="action"></param>
        public static void Cipher(string input, ref string output, bool mode, bool isBackwardsOrSep, CipherType type, int shift = 0,
                                    string key = "", Action<string, string>? action = null)
        {
            switch (type)
            {
                case CipherType.Caesar:
                    if (mode)
                        output = Ciphers.CaesarDecode(isBackwardsOrSep ? Ciphers.Backwards(input) : input, shift);
                    else
                        output = Ciphers.CaesarEncode(isBackwardsOrSep ? Ciphers.Backwards(input) : input, shift);
                    break;
                case CipherType.August:
                    if (mode)
                        output = Ciphers.AugustDecode(isBackwardsOrSep ? Ciphers.Backwards(input) : input);
                    else
                        output = Ciphers.AugustEncode(isBackwardsOrSep ? Ciphers.Backwards(input) : input);
                    break;
                case CipherType.Atbash:
                    output = Ciphers.AtbashCode(isBackwardsOrSep ? Ciphers.Backwards(input) : input);
                    break;
                case CipherType.Vigenere:
                    if (mode)
                        output = Ciphers.VigenereDecode(isBackwardsOrSep ? Ciphers.Backwards(input) : input, key, action);
                    else
                        output = Ciphers.VigenereEncode(isBackwardsOrSep ? Ciphers.Backwards(input) : input, key, action);
                    break;
                case CipherType.Morse:
                    if (mode)
                        output = Ciphers.MorseDecode(input);
                    else
                        output = isBackwardsOrSep ? Ciphers.MorseEncode(input, true) : Ciphers.MorseEncode(input, false);
                    break;
                default: break;
            }
        }

        /// <summary>
        /// Podprogram pro propojení vstupních/výstupních parametrů u ASCII šifry
        /// </summary>
        /// <param name="input"></param>
        /// <param name="output"></param>
        /// <param name="inputSystem"></param>
        /// <param name="outputSystem"></param>
        /// <param name="mode"></param>
        public static void AsciiCipher(string input, ref string output, AsciiChoices inputSystem, AsciiChoices outputSystem, bool mode)
        {
            if (mode)
                output = Ciphers.AsciiDecode(input, inputSystem);
            else
                output = Ciphers.AsciiEncode(input, outputSystem);
        }

        /// <summary>
        /// Podprogram pro propojení vstupních/výstupních parametrů u SHA hashe
        /// </summary>
        /// <param name="input"></param>
        /// <param name="output"></param>
        /// <param name="type"></param>
        public static void ShaCipher(string input, ref string output, ShaTypes type)
        {
            output = !String.IsNullOrEmpty(input) ? Ciphers.HashSha(input, type) : "";
        }

        /// <summary>
        /// Podprogram pro propojení vstupních/výstupních parametrů u MD5 hashe
        /// </summary>
        /// <param name="input"></param>
        /// <param name="output"></param>
        /// <param name="type"></param>
        public static void Md5Cipher(string input, ref string output)
        {
            output = !String.IsNullOrEmpty(input) ? Ciphers.HashMd5(input) : "";
        }

        /// <summary>
        /// Podprogram pro propojení vstupních/výstupních parametrů u RSA hashe
        /// </summary>
        /// <param name="input"></param>
        /// <param name="publicKey"></param>
        /// <param name="privateKey"></param>
        /// <param name="output"></param>
        /// <param name="mode"></param>
        /// <param name="showMsg"></param>
        public static void RsaCipher(string input, string publicKey, string privateKey, ref string output, bool mode, Action<string, string> showMsg)
        {
            if (!String.IsNullOrEmpty(input) && !String.IsNullOrEmpty(publicKey) && !String.IsNullOrEmpty(publicKey))
            {
                if (mode)
                {
                    output = Ciphers.RsaDecode(input, privateKey, showMsg);
                }
                else
                    output = Ciphers.RsaEncode(input, publicKey, showMsg);
            }
        }

        /// <summary>
        /// Podprogram pro zápis do souboru
        /// </summary>
        /// <param name="writer"></param>
        /// <param name="name"></param>
        /// <param name="input"></param>
        /// <param name="output"></param>
        /// <param name="isBackwards"></param>
        /// <param name="mode"></param>
        /// <param name="visibilityIsBackwards"></param>
        public static void WriteToFile(StreamWriter writer, string name, string input, string output, bool isBackwards, bool mode, bool visibilityIsBackwards = false)
        {
            writer.WriteLine(name + " " + (mode ? "- DEKODÉR" : "- ENKODÉR"));
            writer.WriteLine();
            writer.WriteLine("===== vstup " + (mode ? "(šifrovaný)" : "(nešifrovaný)") + " =====");
            if (visibilityIsBackwards) writer.WriteLine("== Pozpátku: " + (isBackwards ? "ano" : "ne"));
            writer.WriteLine();
            writer.WriteLine(input);
            writer.WriteLine();
            writer.WriteLine("===== výstup " + (mode ? "(odšifrovaný)" : "(zašifrovaný)") + " =====");
            writer.WriteLine();
            writer.WriteLine(output);
            writer.WriteLine();
        }

        /// <summary>
        /// Podprogram pro zápis do souboru u šifer s méně parametry
        /// </summary>
        /// <param name="sw"></param>
        /// <param name="name"></param>
        /// <param name="input"></param>
        /// <param name="output"></param>
        /// <param name="type"></param>
        public static void WriteToFileSimple(StreamWriter sw, string name, string input, string output, object? type = null)
        {
            sw.WriteLine(name);
            sw.WriteLine();
            sw.WriteLine("===== vstup =====");
            sw.WriteLine();
            sw.WriteLine(input);
            sw.WriteLine();
            sw.WriteLine("===== výstup =====");
            sw.WriteLine();
            sw.WriteLine(output);
            sw.WriteLine();
            if (type != null) sw.WriteLine("Typ hashe: " + type);
        }

        /// <summary>
        /// Vypíše výsledek hashování do souboru
        /// </summary>
        /// <param name="sw"></param>
        /// <param name="hash"></param>
        /// <param name="path"></param>
        /// <param name="size"></param>
        /// <param name="type"></param>
        public static void WriteHashCalculationsResult(StreamWriter sw, string hash, string path, long size, string type)
        {
            sw.WriteLine("Hash: " + hash);
            sw.WriteLine("Typ hashe: " + type);
            sw.WriteLine("Název souboru: " + Path.GetFileName(path));
            sw.WriteLine("Cesta k souboru: " + path);
            sw.WriteLine("Velikost souboru: " + size + " B");
        }

        // variables
        private int _selectedIndex = 0;
        private Randomizer _rand;
        private string _path = String.Empty;
        private string _path2 = String.Empty;
        private bool _isBusy = false;

        // caesar
        private string _inputTextCaesar = String.Empty;
        private string _outputTextCaesar = String.Empty;
        private int _shiftCaesar = 0;
        private bool _isBackwardsCaesar = false;
        private bool _modeCaesar = false; // false = encode, true = decode

        // august
        private string _inputTextAugust = String.Empty;
        private string _outputTextAugust = String.Empty;
        private bool _isBackwardsAugust = false;
        private bool _modeAugust = false; // false = encode, true = decode

        // atbash
        private string _inputTextAtbash = String.Empty;
        private string _outputTextAtbash = String.Empty;
        private bool _isBackwardsAtbash = false;
        private bool _modeAtbash = false; // false = encode, true = decode

        // vigenere
        private string _inputTextVigenere = String.Empty;
        private string _outputTextVigenere = String.Empty;
        private string _keyVigenere = String.Empty;
        private bool _isBackwardsVigenere = false;
        private bool _modeVigenere = false; // false = encode, true = decode

        // morse
        private string _inputTextMorse = String.Empty;
        private string _outputTextMorse = String.Empty;
        private bool _isSeparatedMorse = true;
        private bool _modeMorse = false; // false = encode, true = decode

        // ascii
        private string _inputTextAscii = String.Empty;
        private string _outputTextAscii = String.Empty;
        private bool _modeAscii = false; // false = encode, true = decode
        private AsciiChoices _selectedInputMode = Models.AsciiChoices.Desítkově;
        private AsciiChoices _selectedOutputMode = Models.AsciiChoices.Binárně;
        private bool _isInputModeEnable = false;
        private bool _isOutputModeEnable = true;

        // sha
        private string _inputTextSha = String.Empty;
        private string _outputTextSha = String.Empty;
        private ShaTypes _selectedShaType = Models.ShaTypes.SHA256;

        // md
        private string _inputTextMd5 = String.Empty;
        private string _outputTextMd5 = String.Empty;

        // rsa
        private string _publicKey = String.Empty;
        private bool _isPublicKeyEnable = true;
        private string _privateKey = String.Empty;
        private bool _isPrivateKeyEnable = false;
        private string _inputTextRsa = String.Empty;
        private string _outputTextRsa = String.Empty;
        private bool _modeRsa = false; // false = encode, true = decode
        private int _bitSize = 1024;

        // rng
        private int _min = 0;
        private int _max = 0;
        private object _generatedNum = 0;
        private bool _isDecimal = false;
        private int _count = 0;
        private string _generatedRow = String.Empty;

        // bruteforce
        private string _bruteScrambled = String.Empty;
        private int _bruteLength = 0;
        private string _bruteResult = String.Empty;
        private int _bruteCombCount = 0;
        private long _bruteTimer = 0;

        public MainViewModel()
        {
            _rand = new Randomizer();
            ImportFileCommand = new RelayCommand(
                () =>
                {
                    OpenFileDialog fileDialog = new()
                    {
                        DefaultExt = ".txt",
                        Filter = "Text documents (.txt)|*.txt"
                    };
                    fileDialog.ShowDialog();
                    if (fileDialog.FileName.Length > 0)
                    {
                        try
                        {
                            using (StreamReader sr = new(fileDialog.FileName, Encoding.UTF8))
                            {
                                switch (SelectedIndex)
                                {
                                    case 0: InputTextCaesar = sr.ReadToEnd(); break;
                                    case 1: InputTextAugust = sr.ReadToEnd(); break;
                                    case 2: InputTextAtbash = sr.ReadToEnd(); break;
                                    case 3: InputTextVigenere = sr.ReadToEnd(); break;
                                    case 4: InputTextMorse = sr.ReadToEnd(); break;
                                    case 5: InputTextAscii = sr.ReadToEnd(); break;
                                    case 6: InputTextSha = sr.ReadToEnd(); break;
                                    case 7: InputTextMd5 = sr.ReadToEnd(); break;
                                    default: break;
                                }
                            }
                            ShowMessage?.Invoke("Soubor úspěšně načten.", "Úspěch");
                        }
                        catch (Exception ex)
                        {
                            ShowMessage?.Invoke(ex.Message, "Chyba");
                        }
                    }
                },
                () => { return SelectedIndex != 10 && SelectedIndex != 9 && SelectedIndex != 8; }
            );
            ExportFileCommand = new RelayCommand(
                () =>
                {
                    SaveFileDialog sfd = new()
                    {
                        DefaultExt = ".txt",
                        Filter = "Text documents (.txt)|*.txt"
                    };
                    sfd.ShowDialog();
                    if (sfd.FileName.Length > 0)
                    {
                        try
                        {
                            Task.Run(() =>
                            {
                                IsBusy = true;
                                using (StreamWriter sw = new(sfd.FileName, false))
                                {
                                    switch (SelectedIndex)
                                    {
                                        case 0:
                                            WriteToFile(sw, "Caesarova šifra", InputTextCaesar, OutputTextCaesar, IsBackwardsCaesar, ModeCaesar, true);
                                            sw.WriteLine("Posun: " + ShiftCaesar);
                                            break;
                                        case 1:
                                            WriteToFile(sw, "Augustova šifra", InputTextAugust, OutputTextAugust, IsBackwardsAugust, ModeAugust, true);
                                            break;
                                        case 2:
                                            WriteToFile(sw, "Atbash", InputTextAtbash, OutputTextAtbash, IsBackwardsAtbash, ModeAtbash, true);
                                            break;
                                        case 3:
                                            WriteToFile(sw, "Vigenėrova šifra", InputTextVigenere, OutputTextVigenere, IsBackwardsVigenere, ModeVigenere, true);
                                            sw.WriteLine("Klíč: " + KeyVigenere);
                                            break;
                                        case 4:
                                            WriteToFile(sw, "Morseovka", InputTextMorse, OutputTextMorse, false, ModeMorse);
                                            break;
                                        case 5:
                                            WriteToFile(sw, "ASCII", InputTextAscii, OutputTextAscii, false, ModeAscii);
                                            if (ModeAscii) sw.WriteLine("Vstupní režim: " + SelectedInputMode);
                                            else sw.WriteLine("Výstupní režim: " + SelectedOutputMode);
                                            break;
                                        case 6:
                                            WriteToFileSimple(sw, "SHA hash", InputTextSha, OutputTextSha, SelectedShaType);
                                            break;
                                        case 7:
                                            WriteToFileSimple(sw, "MD5 hash", InputTextMd5, OutputTextMd5);
                                            break;
                                        case 8:
                                            WriteToFile(sw, "RSA hash", InputTextRsa, OutputTextRsa, false, ModeRsa);
                                            if (ModeRsa)
                                            {
                                                sw.WriteLine("===== Soukromý klíč (podle něj bylo dešifrováno) =====");
                                                sw.WriteLine();
                                                sw.WriteLine(PrivateKey);
                                                sw.WriteLine();
                                                sw.WriteLine("===== Veřejný klíč =====");
                                                sw.WriteLine();
                                                sw.WriteLine(PublicKey);
                                            }
                                            else
                                            {
                                                sw.WriteLine("===== Veřejný klíč (podle něj bylo šifrováno) =====");
                                                sw.WriteLine();
                                                sw.WriteLine(PublicKey);
                                                sw.WriteLine();
                                                sw.WriteLine("===== Soukromý klíč =====");
                                                sw.WriteLine();
                                                sw.WriteLine(PrivateKey);
                                            }
                                            sw.WriteLine();
                                            sw.WriteLine("Velikost klíčů: " + BitSize + " bitů");
                                            break;
                                        case 9:
                                            WriteToFileSimple(sw, "Generátor náhodných čísel", "Min: " + Min + ", Max: " + Max + ", Počet: " + Count, GeneratedRow);
                                            break;
                                        case 10:
                                            WriteToFileSimple(sw, "Jednoduchý bruteforce", "Výchozí znaky: " + BruteScrambled + ", Délka slova: " + BruteLength, "Počet kombinací: " + BruteCombCount + "\nČas : " + BruteTimer + " ms" + "\nKombinace: " + BruteResult);
                                            break;
                                        default: break;
                                    }
                                }
                                IsBusy = false;
                            });                      
                            ShowMessage?.Invoke("Soubor úspěšně uložen.", "Úspěch");
                        }
                        catch (Exception ex)
                        {
                            ShowMessage?.Invoke(ex.Message, "Chyba");
                        }
                    }
                },
                () =>
                {
                    switch (SelectedIndex)
                    {
                        case 0: return !String.IsNullOrEmpty(OutputTextCaesar);
                        case 1: return !String.IsNullOrEmpty(OutputTextAugust);
                        case 2: return !String.IsNullOrEmpty(OutputTextAtbash);
                        case 3: return !String.IsNullOrEmpty(OutputTextVigenere);
                        case 4: return !String.IsNullOrEmpty(OutputTextMorse);
                        case 5: return !String.IsNullOrEmpty(OutputTextAscii);
                        case 6: return !String.IsNullOrEmpty(OutputTextSha);
                        case 7: return !String.IsNullOrEmpty(OutputTextMd5);
                        case 8: return (!String.IsNullOrEmpty(OutputTextRsa) && !String.IsNullOrEmpty(InputTextRsa));
                        case 9: return !String.IsNullOrEmpty(GeneratedRow);
                        case 10: return !String.IsNullOrEmpty(BruteResult);
                        default: return false;
                    }
                }
            );

            SetEncodeCommand = new RelayCommand(
                () =>
                {
                    switch (SelectedIndex)
                    {
                        case 0: ModeCaesar = false; break;
                        case 1: ModeAugust = false; break;
                        case 2: ModeAtbash = false; break;
                        case 3: ModeVigenere = false; break;
                        case 4: ModeMorse = false; break;
                        case 5:
                            ModeAscii = false;
                            IsOutputModeEnable = true;
                            IsInputModeEnable = false;
                            break;
                        case 8: 
                            ModeRsa = false;
                            IsPublicKeyEnable = true;
                            IsPrivateKeyEnable = false;
                            InputTextRsa = String.Empty;
                            OutputTextRsa = String.Empty;
                            if (String.IsNullOrEmpty(PublicKey)) 
                                ShowMessage?.Invoke("Veřejný klíč musí být při šifrování vyplněn. Vygenerujte klíčový pár.", "Chyba");
                            break;
                        default: break;
                    }
                },
                () =>
                {
                    return SelectedIndex switch
                    {
                        0 => ModeCaesar,
                        1 => ModeAugust,
                        2 => ModeAtbash,
                        3 => ModeVigenere,
                        4 => ModeMorse,
                        5 => ModeAscii,
                        8 => ModeRsa,
                        _ => false
                    };
                }
            );
            SetDecodeCommand = new RelayCommand(
                () =>
                {
                    switch (SelectedIndex)
                    {
                        case 0: ModeCaesar = true; break;
                        case 1: ModeAugust = true; break;
                        case 2: ModeAtbash = true; break;
                        case 3: ModeVigenere = true; break;
                        case 4: ModeMorse = true; break;
                        case 5:
                            ModeAscii = true;
                            IsOutputModeEnable = false;
                            IsInputModeEnable = true;
                            break;
                        case 8: 
                            ModeRsa = true;
                            IsPublicKeyEnable = false;
                            IsPrivateKeyEnable = true;
                            InputTextRsa = OutputTextRsa;
                            OutputTextRsa = String.Empty;
                            if (String.IsNullOrEmpty(PrivateKey))
                                ShowMessage?.Invoke("Soukromý klíč musí být při dešifrování vyplněn. Vygenerujte klíčový pár.", "Chyba");                     
                            break;
                        default: break;
                    }
                },
                () =>
                {
                    return SelectedIndex switch
                    {
                        0 => !ModeCaesar,
                        1 => !ModeAugust,
                        2 => !ModeAtbash,
                        3 => !ModeVigenere,
                        4 => !ModeMorse,
                        5 => !ModeAscii,
                        8 => !ModeRsa,
                        _ => false
                    };
                }
            );

            GenerateRandomNumber = new RelayCommand(
                () =>
                {
                    GeneratedNumber = _rand.GenerateRandomNumber(Min, Max, IsDecimal);
                },
                () => { return Max > Min; }
            );
            GenerateRandomRow = new RelayCommand(
                () =>
                {
                    int[] row = _rand.GenerateRandomRow(Min, Max, Count);
                    GeneratedRow = String.Join(", ", row);
                },
                () => { return Max > Min && Count > 0; }
            );

            GenerateKeyPairCommand = new RelayCommand(
                () =>
                {
                    Task.Run(() =>
                    {
                        IsBusy = true;
                        string[] keys = Ciphers.GenerateKeyPairRsa(ShowMessage, BitSize);
                        PublicKey = keys[0];
                        PrivateKey = keys[1];
                        IsBusy = false;
                    });
                },
                () => { return BitSize >= 520 && BitSize <= 4096; }
            );
            ExportRsaKeysToFileCommand = new RelayCommand(
                () =>
                {
                    if (!String.IsNullOrEmpty(PublicKey) && !String.IsNullOrEmpty(PrivateKey))
                    {
                        SaveFileDialog sfd = new()
                        {
                            DefaultExt = ".txt",
                            Filter = "Text documents (.txt)|*.txt"
                        };
                        sfd.ShowDialog();
                        if (sfd.FileName.Length > 0)
                        {
                            Task.Run(() =>
                            {
                                IsBusy = true;
                                try
                                {
                                    using (StreamWriter sw = new(sfd.FileName, false))
                                    {
                                        sw.WriteLine("===== Veřejný klíč =====");
                                        sw.WriteLine();
                                        sw.WriteLine(PublicKey);
                                        sw.WriteLine();
                                        sw.WriteLine("===== Soukromý klíč =====");
                                        sw.WriteLine();
                                        sw.WriteLine(PrivateKey);
                                        sw.WriteLine();
                                        sw.WriteLine("Velikost klíčů: " + BitSize + " bitů");
                                    }
                                    IsBusy = false;
                                    ShowMessage?.Invoke("Soubor úspěšně uložen.", "Úspěch");
                                }
                                catch (Exception ex)
                                {
                                    ShowMessage?.Invoke(ex.Message, "Chyba");
                                }
                                finally
                                {
                                    IsBusy = false;
                                }
                            });
                        }
                    }
                    else
                    {
                        ShowMessage?.Invoke("Nejprve vygenerujte klíčový pár.", "Chyba");
                    }
                },
                () => { return true; /*!String.IsNullOrEmpty(PublicKey) && !String.IsNullOrEmpty(PrivateKey);*/ }
            );

            ComputeShaFromFileCommand = new ParametrizedRelayCommand<string>(
                (param) =>
                {
                    if (Enum.TryParse(param, out ShaTypes type))
                    {
                        string? folderName = Path.GetDirectoryName(PathFile);
                        string newFile = Path.Combine(!String.IsNullOrEmpty(folderName) ? folderName : "", type + ".txt");
                        Task.Run(() =>
                        {
                            IsBusy = true;
                            try
                            {
                                string shaHash = FileCalculations.CalculateSha(PathFile, type);
                                long size = FileCalculations.GetFileSize(PathFile);
                                try
                                {
                                    using (StreamWriter sw = new(newFile, false))
                                    {
                                        WriteHashCalculationsResult(sw, shaHash, PathFile, size, type.ToString());
                                    }
                                    IsBusy = false;
                                    ShowMessage?.Invoke("Hash úspěšně vypočítán a uložen do: " + newFile, "Úspěch");
                                    Process.Start("notepad.exe", newFile);
                                }
                                catch (Exception ex)
                                {
                                    ShowMessage?.Invoke(ex.Message, "Chyba");
                                }
                            }
                            catch (Exception ex)
                            {
                                ShowMessage?.Invoke(ex.Message, "Chyba");
                            }
                            finally
                            {
                                IsBusy = false;
                            }
                        });
                    }
                },
                (p) => { return true; }
            );
            ComputeMd5FromFileCommand = new RelayCommand(
                () =>
                {
                    string? folderName = Path.GetDirectoryName(PathFile);
                    string newFile = Path.Combine(!String.IsNullOrEmpty(folderName) ? folderName : "", "md5.txt");
                    Task.Run(() =>
                    {
                        IsBusy = true;
                        try
                        {
                            string md5Hash = FileCalculations.CalculateMd5(PathFile);
                            long size = FileCalculations.GetFileSize(PathFile);
                            try
                            {
                                using (StreamWriter sw = new(newFile, false))
                                {
                                    WriteHashCalculationsResult(sw, md5Hash, PathFile, size, "MD5");
                                }
                                IsBusy = false;
                                ShowMessage?.Invoke("Hash úspěšně vypočítán a uložen do: " + newFile, "Úspěch");
                                Process.Start("notepad.exe", newFile);
                            }
                            catch (Exception ex)
                            {
                                ShowMessage?.Invoke(ex.Message, "Chyba");
                            }
                        }
                        catch (Exception ex)
                        {
                            ShowMessage?.Invoke(ex.Message, "Chyba");
                        }
                        finally
                        {
                            IsBusy = false;
                        }
                    });
                },
                () => { return true; }
            );
            ComputeCrc32FromFileCommand = new RelayCommand(
                () =>
                {
                    string? folderName = Path.GetDirectoryName(PathFile);
                    string newFile = Path.Combine(!String.IsNullOrEmpty(folderName) ? folderName : "", "crc32.txt");
                    Task.Run(() =>
                    {
                        IsBusy = true;
                        try
                        {
                            string crc32Hash = FileCalculations.CalculateCrc32(PathFile);
                            long size = FileCalculations.GetFileSize(PathFile);
                            try
                            {
                                using (StreamWriter sw = new(newFile, false))
                                {
                                    WriteHashCalculationsResult(sw, crc32Hash, PathFile, size, "CRC-32");
                                }
                                IsBusy = false;
                                ShowMessage?.Invoke("Hash úspěšně vypočítán a uložen do: " + newFile, "Úspěch");
                                Process.Start("notepad.exe", newFile);
                            }
                            catch (Exception ex)
                            {
                                ShowMessage?.Invoke(ex.Message, "Chyba");
                            }
                        }
                        catch (Exception ex)
                        {
                            ShowMessage?.Invoke(ex.Message, "Chyba");
                        }
                        finally
                        {
                            IsBusy = false;
                        }
                    });
                },
                () => { return true; }
            );
            ComputeAllHashesFromFileCommand = new RelayCommand(
                () =>
                {
                    string? folderName = Path.GetDirectoryName(PathFile);
                    string newFile = Path.Combine(!String.IsNullOrEmpty(folderName) ? folderName : "", "all.txt");
                    Task.Run(() =>
                    {
                        IsBusy = true;
                        try
                        {
                            string sha1Hash = FileCalculations.CalculateSha(PathFile, ShaTypes.SHA1);
                            string sha256Hash = FileCalculations.CalculateSha(PathFile, ShaTypes.SHA256);
                            string sha384Hash = FileCalculations.CalculateSha(PathFile, ShaTypes.SHA384);
                            string sha512Hash = FileCalculations.CalculateSha(PathFile, ShaTypes.SHA512);
                            string md5Hash = FileCalculations.CalculateMd5(PathFile);
                            string crc32Hash = FileCalculations.CalculateCrc32(PathFile);
                            long size = FileCalculations.GetFileSize(PathFile);
                            try
                            {
                                using (StreamWriter sw = new(newFile, false))
                                {
                                    sw.WriteLine("SHA-1: " + sha1Hash);
                                    sw.WriteLine("SHA-256: " + sha256Hash);
                                    sw.WriteLine("SHA-384: " + sha384Hash);
                                    sw.WriteLine("SHA-512: " + sha512Hash);
                                    sw.WriteLine("MD5: " + md5Hash);
                                    sw.WriteLine("CRC-32: " + crc32Hash);
                                    sw.WriteLine("Název souboru: " + Path.GetFileName(PathFile));
                                    sw.WriteLine("Cesta k souboru: " + PathFile);
                                    sw.WriteLine("Velikost souboru: " + size + " B");
                                }
                                IsBusy = false;
                                ShowMessage?.Invoke("Hashe úspěšně vypočítány a uloženy do: " + newFile, "Úspěch");
                                Process.Start("notepad.exe", newFile);
                            }
                            catch (Exception ex)
                            {
                                ShowMessage?.Invoke(ex.Message, "Chyba");
                            }
                        }
                        catch (Exception ex)
                        {
                            ShowMessage?.Invoke(ex.Message, "Chyba");
                        }
                        finally
                        {
                            IsBusy = false;
                        }
                    });
                },
                () => { return true; }
             );
            CompareFilesAccordingToHashCommand = new RelayCommand(
                () =>
                {
                    string? folderName = Path.GetDirectoryName(PathFile);
                    string newFile = Path.Combine(!String.IsNullOrEmpty(folderName) ? folderName : "", "comparation.txt");
                    Task.Run(() =>
                    {
                        try
                        {
                            OpenFileDialog fileDialog = new();
                            fileDialog.ShowDialog();
                            PathFile = fileDialog.FileName;
                            if (PathFile.Length > 0)
                            {
                                IsBusy = true;
                                string sha1Hash = FileCalculations.CalculateSha(PathFile, ShaTypes.SHA1);
                                string sha256Hash = FileCalculations.CalculateSha(PathFile, ShaTypes.SHA256);
                                string sha384Hash = FileCalculations.CalculateSha(PathFile, ShaTypes.SHA384);
                                string sha512Hash = FileCalculations.CalculateSha(PathFile, ShaTypes.SHA512);
                                string md5Hash = FileCalculations.CalculateMd5(PathFile);
                                string crc32Hash = FileCalculations.CalculateCrc32(PathFile);
                                long size = FileCalculations.GetFileSize(PathFile);
                                try
                                {
                                    using (StreamWriter sw = new(newFile, false))
                                    {
                                        sw.WriteLine("=====První soubor=====");
                                        sw.WriteLine("SHA-1: " + sha1Hash);
                                        sw.WriteLine("SHA-256: " + sha256Hash);
                                        sw.WriteLine("SHA-384: " + sha384Hash);
                                        sw.WriteLine("SHA-512: " + sha512Hash);
                                        sw.WriteLine("MD5: " + md5Hash);
                                        sw.WriteLine("CRC-32: " + crc32Hash);
                                        sw.WriteLine("Název souboru: " + Path.GetFileName(PathFile));
                                        sw.WriteLine("Cesta k souboru: " + PathFile);
                                        sw.WriteLine("Velikost souboru: " + size + " B");
                                        sw.WriteLine();
                                    }
                                    ShowMessage?.Invoke("Hashe u souboru " + Path.GetFileName(PathFile) + " úspěšně vypočítány. Nyní vyberte druhý soubor.", "Úspěch");

                                    OpenFileDialog fileDialog2 = new();
                                    fileDialog2.ShowDialog();
                                    PathFile2 = fileDialog2.FileName;
                                    if (PathFile2.Length > 0)
                                    {
                                        string sha1Hashsec = FileCalculations.CalculateSha(PathFile2, ShaTypes.SHA1);
                                        string sha256Hashsec = FileCalculations.CalculateSha(PathFile2, ShaTypes.SHA256);
                                        string sha384Hashsec = FileCalculations.CalculateSha(PathFile2, ShaTypes.SHA384);
                                        string sha512Hashsec = FileCalculations.CalculateSha(PathFile2, ShaTypes.SHA512);
                                        string md5Hashsec = FileCalculations.CalculateMd5(PathFile2);
                                        string crc32Hashsec = FileCalculations.CalculateCrc32(PathFile2);
                                        long sizesec = FileCalculations.GetFileSize(PathFile2);
                                        try
                                        {
                                            using StreamWriter sw = new(newFile, true);
                                            sw.WriteLine("=====Druhý soubor=====");
                                            sw.WriteLine("SHA-1: " + sha1Hashsec);
                                            sw.WriteLine("SHA-256: " + sha256Hashsec);
                                            sw.WriteLine("SHA-384: " + sha384Hashsec);
                                            sw.WriteLine("SHA-512: " + sha512Hashsec);
                                            sw.WriteLine("MD5: " + md5Hashsec);
                                            sw.WriteLine("CRC-32: " + crc32Hashsec);
                                            sw.WriteLine("Název souboru: " + Path.GetFileName(PathFile2));
                                            sw.WriteLine("Cesta k souboru: " + PathFile2);
                                            sw.WriteLine("Velikost souboru: " + sizesec + " B");
                                            sw.WriteLine();
                                            sw.WriteLine("=====Výsledek=====");
                                            sw.WriteLine(sha1Hash == sha1Hashsec ? "SHA-1: shoda" : "SHA-1: NEshoda");
                                            sw.WriteLine(sha256Hash == sha256Hashsec ? "SHA-256: shoda" : "SHA-256: NEshoda");
                                            sw.WriteLine(sha384Hash == sha384Hashsec ? "SHA-384: shoda" : "SHA-384: NEshoda");
                                            sw.WriteLine(sha512Hash == sha512Hashsec ? "SHA-512: shoda" : "SHA-512: NEshoda");
                                            sw.WriteLine(md5Hash == md5Hashsec ? "MD5: shoda" : "MD5: NEshoda");
                                            sw.WriteLine(crc32Hash == crc32Hashsec ? "CRC-32: shoda" : "CRC-32: NEshoda");
                                        }
                                        catch (Exception ex)
                                        {
                                            ShowMessage?.Invoke(ex.Message, "Chyba");
                                        }
                                        ShowMessage?.Invoke("Oba soubory úspěšně porovnány. Výsledek je v souboru " + newFile, "Úspěch");
                                        Process.Start("notepad.exe", newFile);
                                        IsBusy = false;
                                    }
                                    else
                                    {
                                        ShowMessage?.Invoke("Nebyl vybrán druhý soubor.", "Chyba");
                                        IsBusy = false;
                                    }
                                }
                                catch (Exception ex)
                                {
                                    ShowMessage?.Invoke(ex.Message, "Chyba");
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            ShowMessage?.Invoke(ex.Message, "Chyba");
                        }
                        finally
                        {
                            IsBusy = false;
                        }
                    });
                },
                () => { return true; }
            );

            BruteForceCommand = new RelayCommand(
                () =>
                {
                    Task.Run(() =>
                    {
                        IsBusy = true;
                        Stopwatch stopwatch = Stopwatch.StartNew();
                        var result = BruteForce.GetPermutations(BruteScrambled, BruteLength);
                        HashSet<string> hs = new(result); // pro odstranění duplicit
                        BruteResult = String.Join(", ", hs);
                        BruteCombCount = hs.Count;
                        stopwatch.Stop();
                        BruteTimer = stopwatch.ElapsedMilliseconds;
                        IsBusy = false;
                    });             
                },
                () => { return !String.IsNullOrEmpty(BruteScrambled) && BruteLength > 0 && BruteLength <= 6; }
            );
        }

        // commands
        public RelayCommand ImportFileCommand { get; set; } // importuje vstupní data
        public RelayCommand ExportFileCommand { get; set; } // exportuje výstupní data
        public RelayCommand SetEncodeCommand { get; set; } // zašifruje
        public RelayCommand SetDecodeCommand { get; set; } // odšifruje
        public RelayCommand GenerateRandomNumber { get; set; }
        public RelayCommand GenerateRandomRow { get; set; }
        public RelayCommand GenerateKeyPairCommand { get; set; }
        public RelayCommand ComputeMd5FromFileCommand { get; set; }
        public RelayCommand ComputeCrc32FromFileCommand { get; set; }
        public RelayCommand ComputeAllHashesFromFileCommand { get; set; }
        public RelayCommand CompareFilesAccordingToHashCommand { get; set; }
        public RelayCommand ExportRsaKeysToFileCommand { get; set; }
        public RelayCommand BruteForceCommand { get; set; }
        public ParametrizedRelayCommand<string> ComputeShaFromFileCommand { get; set; }

        // delegates
        public Action<string, string> ShowMessage { get; set; }

        // properties
        public int SelectedIndex
        {
            get { return _selectedIndex; }
            set
            {
                _selectedIndex = value;
                NotifyPropertyChanged();
                ImportFileCommand.RaiseCanExecuteChanged();
                ExportFileCommand.RaiseCanExecuteChanged();
                SetDecodeCommand.RaiseCanExecuteChanged();
                SetEncodeCommand.RaiseCanExecuteChanged();
            }
        }
        public string PathFile
        {
            get => _path;
            set { _path = value; NotifyPropertyChanged(); }
        }
        public string PathFile2
        {
            get => _path2;
            set { _path2 = value; NotifyPropertyChanged(); }
        }
        public bool IsBusy
        {
            get => _isBusy;
            set { _isBusy = value; NotifyPropertyChanged(); }
        }

        // caesar
        public string InputTextCaesar
        {
            get => _inputTextCaesar;
            set
            {
                _inputTextCaesar = value;
                Cipher(_inputTextCaesar, ref _outputTextCaesar, _modeCaesar, _isBackwardsCaesar, CipherType.Caesar, _shiftCaesar);
                NotifyPropertyChanged();
                ExportFileCommand.RaiseCanExecuteChanged();
            }
        }
        public string OutputTextCaesar
        {
            get => _outputTextCaesar;
            set
            {
                _outputTextCaesar = value;
                Cipher(_inputTextCaesar, ref _outputTextCaesar, _modeCaesar, _isBackwardsCaesar, CipherType.Caesar, _shiftCaesar);
                NotifyPropertyChanged();
                ExportFileCommand.RaiseCanExecuteChanged();
            }
        }
        public int ShiftCaesar
        {
            get => _shiftCaesar;
            set
            {
                _shiftCaesar = value;
                Cipher(_inputTextCaesar, ref _outputTextCaesar, _modeCaesar, _isBackwardsCaesar, CipherType.Caesar, _shiftCaesar);
                NotifyPropertyChanged();
            }
        }
        public bool IsBackwardsCaesar
        {
            get => _isBackwardsCaesar;
            set
            {
                _isBackwardsCaesar = value;
                Cipher(_inputTextCaesar, ref _outputTextCaesar, _modeCaesar, _isBackwardsCaesar, CipherType.Caesar, _shiftCaesar);
                NotifyPropertyChanged();
            }
        }
        public bool ModeCaesar
        {
            get => _modeCaesar;
            set
            {
                _modeCaesar = value;
                Cipher(_inputTextCaesar, ref _outputTextCaesar, _modeCaesar, _isBackwardsCaesar, CipherType.Caesar, _shiftCaesar);
                NotifyPropertyChanged();
                SetDecodeCommand.RaiseCanExecuteChanged();
                SetEncodeCommand.RaiseCanExecuteChanged();
            }
        }

        // august
        public string InputTextAugust
        {
            get => _inputTextAugust;
            set
            {
                _inputTextAugust = value;
                Cipher(_inputTextAugust, ref _outputTextAugust, _modeAugust, _isBackwardsAugust, CipherType.August);
                NotifyPropertyChanged();
                ExportFileCommand.RaiseCanExecuteChanged();
            }
        }
        public string OutputTextAugust
        {
            get => _outputTextAugust;
            set
            {
                _outputTextAugust = value;
                Cipher(_inputTextAugust, ref _outputTextAugust, _modeAugust, _isBackwardsAugust, CipherType.August);
                NotifyPropertyChanged();
                ExportFileCommand.RaiseCanExecuteChanged();
            }
        }
        public bool IsBackwardsAugust
        {
            get => _isBackwardsAugust;
            set
            {
                _isBackwardsAugust = value;
                Cipher(_inputTextAugust, ref _outputTextAugust, _modeAugust, _isBackwardsAugust, CipherType.August);
                NotifyPropertyChanged();
            }
        }
        public bool ModeAugust
        {
            get => _modeAugust;
            set
            {
                _modeAugust = value;
                Cipher(_inputTextAugust, ref _outputTextAugust, _modeAugust, _isBackwardsAugust, CipherType.August);
                NotifyPropertyChanged();
                SetDecodeCommand.RaiseCanExecuteChanged();
                SetEncodeCommand.RaiseCanExecuteChanged();
            }
        }

        // atbash
        public string InputTextAtbash
        {
            get => _inputTextAtbash;
            set
            {
                _inputTextAtbash = value;
                Cipher(_inputTextAtbash, ref _outputTextAtbash, _modeAtbash, _isBackwardsAtbash, CipherType.Atbash);
                NotifyPropertyChanged();
                ExportFileCommand.RaiseCanExecuteChanged();
            }
        }
        public string OutputTextAtbash
        {
            get => _outputTextAtbash;
            set
            {
                _outputTextAtbash = value;
                Cipher(_inputTextAtbash, ref _outputTextAtbash, _modeAtbash, _isBackwardsAtbash, CipherType.Atbash);
                NotifyPropertyChanged();
                ExportFileCommand.RaiseCanExecuteChanged();
            }
        }
        public bool IsBackwardsAtbash
        {
            get => _isBackwardsAtbash;
            set
            {
                _isBackwardsAtbash = value;
                Cipher(_inputTextAtbash, ref _outputTextAtbash, _modeAtbash, _isBackwardsAtbash, CipherType.Atbash);
                NotifyPropertyChanged();
            }
        }
        public bool ModeAtbash
        {
            get => _modeAtbash;
            set
            {
                _modeAtbash = value;
                Cipher(_inputTextAtbash, ref _outputTextAtbash, _modeAtbash, _isBackwardsAtbash, CipherType.Atbash);
                NotifyPropertyChanged();
                SetDecodeCommand.RaiseCanExecuteChanged();
                SetEncodeCommand.RaiseCanExecuteChanged();
            }
        }

        // vigenere
        public string InputTextVigenere
        {
            get => _inputTextVigenere;
            set
            {
                _inputTextVigenere = value;
                Cipher(_inputTextVigenere, ref _outputTextVigenere, _modeVigenere, _isBackwardsVigenere, CipherType.Vigenere, 0, _keyVigenere, ShowMessage);
                NotifyPropertyChanged();
                ExportFileCommand.RaiseCanExecuteChanged();
            }
        }
        public string OutputTextVigenere
        {
            get => _outputTextVigenere;
            set
            {
                _outputTextVigenere = value;
                Cipher(_inputTextVigenere, ref _outputTextVigenere, _modeVigenere, _isBackwardsVigenere, CipherType.Vigenere, 0, _keyVigenere, ShowMessage);
                NotifyPropertyChanged();
                ExportFileCommand.RaiseCanExecuteChanged();
            }
        }
        public string KeyVigenere
        {
            get => _keyVigenere;
            set
            {
                _keyVigenere = value;
                Cipher(_inputTextVigenere, ref _outputTextVigenere, _modeVigenere, _isBackwardsVigenere, CipherType.Vigenere, 0, _keyVigenere, ShowMessage);
                NotifyPropertyChanged();
            }
        }
        public bool IsBackwardsVigenere
        {
            get => _isBackwardsVigenere;
            set
            {
                _isBackwardsVigenere = value;
                Cipher(_inputTextVigenere, ref _outputTextVigenere, _modeVigenere, _isBackwardsVigenere, CipherType.Vigenere, 0, _keyVigenere, ShowMessage);
                NotifyPropertyChanged();
            }
        }
        public bool ModeVigenere
        {
            get => _modeVigenere;
            set
            {
                _modeVigenere = value;
                Cipher(_inputTextVigenere, ref _outputTextVigenere, _modeVigenere, _isBackwardsVigenere, CipherType.Vigenere, 0, _keyVigenere, ShowMessage);
                NotifyPropertyChanged();
                SetDecodeCommand.RaiseCanExecuteChanged();
                SetEncodeCommand.RaiseCanExecuteChanged();
            }
        }

        // morse
        public string InputTextMorse
        {
            get => _inputTextMorse;
            set
            {
                _inputTextMorse = value;
                Cipher(_inputTextMorse, ref _outputTextMorse, _modeMorse, _isSeparatedMorse, CipherType.Morse);
                NotifyPropertyChanged();
                ExportFileCommand.RaiseCanExecuteChanged();
            }
        }
        public string OutputTextMorse
        {
            get => _outputTextMorse;
            set
            {
                _outputTextMorse = value;
                Cipher(_inputTextMorse, ref _outputTextMorse, _modeMorse, _isSeparatedMorse, CipherType.Morse);
                NotifyPropertyChanged();
                ExportFileCommand.RaiseCanExecuteChanged();
            }
        }
        public bool IsSeparatedMorse
        {
            get => _isSeparatedMorse;
            set
            {
                _isSeparatedMorse = value;
                Cipher(_inputTextMorse, ref _outputTextMorse, _modeMorse, _isSeparatedMorse, CipherType.Morse);
                NotifyPropertyChanged();
            }
        }
        public bool ModeMorse
        {
            get => _modeMorse;
            set
            {
                _modeMorse = value;
                Cipher(_inputTextMorse, ref _outputTextMorse, _modeMorse, _isSeparatedMorse, CipherType.Morse);
                NotifyPropertyChanged();
                SetDecodeCommand.RaiseCanExecuteChanged();
                SetEncodeCommand.RaiseCanExecuteChanged();
            }
        }

        // ascii
        public static List<AsciiChoices> AsciiChoices
        {
            get => Enum.GetValues(typeof(AsciiChoices)).Cast<AsciiChoices>().ToList();
        }
        public string InputTextAscii
        {
            get => _inputTextAscii;
            set
            {
                _inputTextAscii = value;
                AsciiCipher(_inputTextAscii, ref _outputTextAscii, _selectedInputMode, _selectedOutputMode, _modeAscii);
                NotifyPropertyChanged();
                ExportFileCommand.RaiseCanExecuteChanged();
            }
        }
        public string OutputTextAscii
        {
            get => _outputTextAscii;
            set
            {
                _outputTextAscii = value;
                AsciiCipher(_inputTextAscii, ref _outputTextAscii, _selectedInputMode, _selectedOutputMode, _modeAscii);
                NotifyPropertyChanged();
                ExportFileCommand.RaiseCanExecuteChanged();
            }
        }
        public AsciiChoices SelectedInputMode
        {
            get => _selectedInputMode;
            set
            {
                _selectedInputMode = value;
                AsciiCipher(_inputTextAscii, ref _outputTextAscii, _selectedInputMode, _selectedOutputMode, _modeAscii);
                NotifyPropertyChanged();
            }
        }
        public AsciiChoices SelectedOutputMode
        {
            get => _selectedOutputMode;
            set
            {
                _selectedOutputMode = value;
                AsciiCipher(_inputTextAscii, ref _outputTextAscii, _selectedInputMode, _selectedOutputMode, _modeAscii);
                NotifyPropertyChanged();
            }
        }
        public bool ModeAscii
        {
            get => _modeAscii;
            set
            {
                _modeAscii = value;
                AsciiCipher(_inputTextAscii, ref _outputTextAscii, _selectedInputMode, _selectedOutputMode, _modeAscii);
                NotifyPropertyChanged();
                SetDecodeCommand.RaiseCanExecuteChanged();
                SetEncodeCommand.RaiseCanExecuteChanged();
            }
        }
        public bool IsInputModeEnable
        {
            get => _isInputModeEnable;
            set
            {
                _isInputModeEnable = value;
                NotifyPropertyChanged();
                SetDecodeCommand.RaiseCanExecuteChanged();
                SetEncodeCommand.RaiseCanExecuteChanged();
            }
        }
        public bool IsOutputModeEnable
        {
            get => _isOutputModeEnable;
            set
            {
                _isOutputModeEnable = value;
                NotifyPropertyChanged();
                SetDecodeCommand.RaiseCanExecuteChanged();
                SetEncodeCommand.RaiseCanExecuteChanged();
            }
        }

        // sha
        public static List<ShaTypes> ShaList
        {
            get => Enum.GetValues(typeof(ShaTypes)).Cast<ShaTypes>().ToList();
        }
        public string InputTextSha
        {
            get => _inputTextSha;
            set
            {
                _inputTextSha = value;
                ShaCipher(_inputTextSha, ref _outputTextSha, _selectedShaType);
                NotifyPropertyChanged();
                ExportFileCommand.RaiseCanExecuteChanged();
            }
        }
        public string OutputTextSha
        {
            get => _outputTextSha;
            set
            {
                _outputTextSha = value;
                ShaCipher(_inputTextSha, ref _outputTextSha, _selectedShaType);
                NotifyPropertyChanged();
                ExportFileCommand.RaiseCanExecuteChanged();
            }
        }
        public ShaTypes SelectedShaType
        {
            get => _selectedShaType;
            set
            {
                _selectedShaType = value;
                ShaCipher(_inputTextSha, ref _outputTextSha, _selectedShaType);
                NotifyPropertyChanged();
            }
        }

        // md5
        public string InputTextMd5
        {
            get => _inputTextMd5;
            set
            {
                _inputTextMd5 = value;
                Md5Cipher(_inputTextMd5, ref _outputTextMd5);
                NotifyPropertyChanged();
                ExportFileCommand.RaiseCanExecuteChanged();
            }
        }
        public string OutputTextMd5
        {
            get => _outputTextMd5;
            set
            {
                _outputTextMd5 = value;
                Md5Cipher(_inputTextMd5, ref _outputTextMd5);
                NotifyPropertyChanged();
                ExportFileCommand.RaiseCanExecuteChanged();
            }
        }

        // rsa
        public string InputTextRsa
        {
            get => _inputTextRsa;
            set
            {
                _inputTextRsa = value;
                RsaCipher(_inputTextRsa, _publicKey, _privateKey, ref _outputTextRsa, _modeRsa, ShowMessage);
                NotifyPropertyChanged();
                ExportFileCommand.RaiseCanExecuteChanged();
            }
        }
        public string OutputTextRsa
        {
            get => _outputTextRsa;
            set
            {
                _outputTextRsa = value;
                RsaCipher(_inputTextRsa, _publicKey, _privateKey, ref _outputTextRsa, _modeRsa, ShowMessage);
                NotifyPropertyChanged();
                ExportFileCommand.RaiseCanExecuteChanged();
            }
        }
        public string PublicKey
        {

            get => _publicKey;
            set
            {
                _publicKey = value;
                RsaCipher(_inputTextRsa, _publicKey, _privateKey, ref _outputTextRsa, _modeRsa, ShowMessage);
                NotifyPropertyChanged();
                //SetDecodeCommand.RaiseCanExecuteChanged();
                //SetEncodeCommand.RaiseCanExecuteChanged();
                //ExportRsaKeysToFileCommand.RaiseCanExecuteChanged();
            }

        }
        public bool IsPublicKeyEnable
        {
            get => _isPublicKeyEnable;
            set
            {
                _isPublicKeyEnable = value;
                NotifyPropertyChanged();
            }
        }
        public string PrivateKey
        {
            get => _privateKey;
            set
            {
                _privateKey = value;
                RsaCipher(_inputTextRsa, _publicKey, _privateKey, ref _outputTextRsa, _modeRsa, ShowMessage);
                NotifyPropertyChanged();
                //SetDecodeCommand.RaiseCanExecuteChanged();
                //SetEncodeCommand.RaiseCanExecuteChanged();
                //ExportRsaKeysToFileCommand.RaiseCanExecuteChanged();
            }
        }
        public bool IsPrivateKeyEnable
        {
            get => _isPrivateKeyEnable;
            set
            {
                _isPrivateKeyEnable = value;
                NotifyPropertyChanged();
            }
        }
        public bool ModeRsa
        {
            get => _modeRsa;
            set
            {
                _modeRsa = value;
                //RsaCipher(_inputTextRsa, _publicKey, _privateKey, ref _outputTextRsa, _modeRsa, ShowMessage);
                NotifyPropertyChanged();
                SetDecodeCommand.RaiseCanExecuteChanged();
                SetEncodeCommand.RaiseCanExecuteChanged();
            }
        }
        public int BitSize
        {
            get => _bitSize;
            set
            {
                _bitSize = value;
                NotifyPropertyChanged();
                GenerateKeyPairCommand.RaiseCanExecuteChanged();
            }
        }

        // rng
        public int Min
        {
            get => _min;
            set
            {
                _min = value;
                NotifyPropertyChanged();
                GenerateRandomNumber.RaiseCanExecuteChanged();
                GenerateRandomRow.RaiseCanExecuteChanged();
            }
        }
        public int Max
        {
            get => _max;
            set
            {
                _max = value;
                NotifyPropertyChanged();
                GenerateRandomNumber.RaiseCanExecuteChanged();
                GenerateRandomRow.RaiseCanExecuteChanged();
            }
        }
        public object GeneratedNumber
        {
            get => _generatedNum;
            set
            {
                _generatedNum = value;
                NotifyPropertyChanged();
            }
        }
        public bool IsDecimal
        {
            get => _isDecimal;
            set
            {
                _isDecimal = value;
                NotifyPropertyChanged();
            }
        }
        public int Count
        {
            get => _count;
            set
            {
                _count = value;
                NotifyPropertyChanged();
                GenerateRandomRow.RaiseCanExecuteChanged();
            }
        }
        public string GeneratedRow
        {
            get => _generatedRow;
            set
            {
                _generatedRow = value;
                NotifyPropertyChanged();
                ExportFileCommand.RaiseCanExecuteChanged();
            }
        }

        // bruteforce
        public string BruteScrambled
        {
            get => _bruteScrambled;
            set
            {
                _bruteScrambled = value;
                NotifyPropertyChanged();
                Application.Current.Dispatcher.InvokeAsync(() => BruteForceCommand.RaiseCanExecuteChanged());
            }
        }
        public int BruteLength
        {
            get => _bruteLength;
            set
            {
                _bruteLength = value;
                NotifyPropertyChanged();
                Application.Current.Dispatcher.InvokeAsync(() => BruteForceCommand.RaiseCanExecuteChanged());
            }
        }
        public string BruteResult
        {
            get => _bruteResult;
            set
            {
                _bruteResult = value;
                NotifyPropertyChanged();
                Application.Current.Dispatcher.InvokeAsync(() => ExportFileCommand.RaiseCanExecuteChanged());
            }
        }
        public int BruteCombCount
        {

            get => _bruteCombCount;
            set
            {
                _bruteCombCount = value;
                NotifyPropertyChanged();
            }
        }
        public long BruteTimer
        {
            get => _bruteTimer;
            set
            {
                _bruteTimer = value;
                NotifyPropertyChanged();
            }        
        }
    }
}