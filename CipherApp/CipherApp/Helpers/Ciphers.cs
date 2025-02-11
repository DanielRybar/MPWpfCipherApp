using CipherApp.Models;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace CipherApp.Helpers
{
    public static class Ciphers
    {
        /// <summary>
        /// Podprogram pro odebrání diakritiky ze slova
        /// </summary>
        /// <param name="word"></param>
        private static void RemoveDiacritics(ref string word)
        {
            string normalizedText = word.Normalize(NormalizationForm.FormD);
            StringBuilder sb = new StringBuilder();
            foreach (var x in normalizedText)
            {
                if (CharUnicodeInfo.GetUnicodeCategory(x) != UnicodeCategory.NonSpacingMark)
                {
                    sb.Append(x);
                }
            }

            word = sb.ToString().Normalize(NormalizationForm.FormC);
        }

        /// <summary>
        /// Kontroluje, jestli je řetězec v binární soustavě
        /// </summary>
        /// <param name="s"></param>
        /// <returns></returns>
        private static bool IsBinary(string s)
        {
            foreach (var c in s)
                if (c != '0' && c != '1')
                    return false;
            return true;
        }

        /// <summary>
        /// Kontroluje, jestli je řetězec v osmičkové soustavě
        /// </summary>
        /// <param name="s"></param>
        /// <returns></returns>
        private static bool IsOctal(string s)
        {
            foreach (var c in s)
                if (c != '0' && c != '1' && c != '2' && c != '3' && c != '4' && c != '5' && c != '6' && c != '7')
                    return false;
            return true;
        }

        /// <summary>
        /// Odšifruje text zašifrovaný Caesarovou šifrou
        /// </summary>
        /// <param name="input"></param>
        /// <param name="shift"></param>
        /// <returns></returns>
        public static string CaesarDecode(string input, int shift)
        {
            return CaesarEncode(input, 26 - shift);
        }

        /// <summary>
        /// Zašifruje text pomocí Caesarovy šifry
        /// </summary>
        /// <param name="input"></param>
        /// <param name="shift"></param>
        /// <returns></returns>
        public static string CaesarEncode(string input, int shift)
        {
            RemoveDiacritics(ref input);
            string output = String.Empty;
            foreach (char ch in input)
            {
                if (Char.IsLetter(ch))
                {
                    char offset = char.IsUpper(ch) ? 'A' : 'a';
                    output += (char)(((ch + shift - offset) % 26) + offset);
                }
                else
                {
                    output += ch;
                }
            }
            return output;
        }

        /// <summary>
        /// Obrací text (např. "ahoj" -> "joha")
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        public static string Backwards(string input)
        {
            RemoveDiacritics(ref input);
            char[] charArray = input.ToCharArray();
            Array.Reverse(charArray);
            return new string(charArray);
        }

        // Augustova šifra - při šifrování posun jen o jedno místo (A -> B, B -> C, ..., akorát že Z -> AA)
        /// <summary>
        /// Odšifruje text zašifrovaný Augustovou šifrou 
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        public static string AugustDecode(string input)
        {
            RemoveDiacritics(ref input);
            string output = String.Empty;
            foreach (char ch in input)
            {
                if (Char.IsLetter(ch))
                {
                    char offset = char.IsUpper(ch) ? 'A' : 'a';
                    if (ch == 'a')
                    {
                        output += ch;
                        output = output.Replace("aa", "z");
                    }
                    else if (ch == 'A')
                    {
                        output += ch;
                        output = output.Replace("AA", "Z");
                    }
                    else
                        output += (char)(((ch - 1 - offset) % 26) + offset);
                }
                else
                {
                    output += ch;
                }
            }
            return output;
        }

        /// <summary>
        /// Zašifruje text pomocí Augustovy šifry 
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        public static string AugustEncode(string input)
        {
            RemoveDiacritics(ref input);
            string output = String.Empty;
            foreach (char ch in input)
            {
                if (Char.IsLetter(ch))
                {
                    char offset = char.IsUpper(ch) ? 'A' : 'a';
                    if (ch == 'z')
                        output += "aa";
                    else if (ch == 'Z')
                        output += "AA";
                    else
                        output += (char)(((ch + 1 - offset) % 26) + offset);
                }
                else
                {
                    output += ch;
                }
            }
            return output;
        }

        /// <summary>
        /// Zašifruje/odšifruje text pomocí šifry Atbash (obě tyto funkce jsou stejné)
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        public static string AtbashCode(string input)
        {
            RemoveDiacritics(ref input);
            string output = String.Empty;
            foreach (char ch in input)
            {
                if (Char.IsLetter(ch))
                {
                    char offset = char.IsUpper(ch) ? 'A' : 'a';
                    output += (char)(((25 - (ch - offset)) % 26) + offset);
                }
                else
                {
                    output += ch;
                }
            }
            return output;
        }

        /// <summary>
        /// Odšifruje text pomocí Vigenérovy šifry
        /// </summary>
        /// <param name="input"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        public static string VigenereDecode(string input, string key, Action<string, string>? action, bool mode = false)
        {
            RemoveDiacritics(ref input);
            bool error = false;

            for (int i = 0; i < key.Length; i++)
            {
                if (!char.IsLetter(key[i]) && !char.IsDigit(key[i]))
                    error = true;
            }

            if (error)
                action?.Invoke("Klíč obsahuje nealfanumerické znaky.", "Chyba");

            string output = String.Empty;
            int j = 0;

            for (int i = 0; i < input.Length; i++)
            {
                if (Char.IsLetter(input[i]) && key.Length > 0)
                {
                    bool isUpper = char.IsUpper(input[i]);
                    char offset = isUpper ? 'A' : 'a';
                    int keyIndex = (i - j) % key.Length;
                    int k = (isUpper ? char.ToUpper(key[keyIndex]) : char.ToLower(key[keyIndex])) - offset;

                    k = mode ? k : -k;
                    char ch = (char)(((input[i] + k - offset) % 26 + 26) % 26 + offset);
                    output += ch;
                }
                else
                {
                    output += input[i];
                    j++;
                }
            }
            return output;
        }

        /// <summary>
        /// Zašifruje text pomocí Vigenérovy šifry (čísla v klíči povolena)
        /// </summary>
        /// <param name="input"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        public static string VigenereEncode(string input, string key, Action<string, string>? action)
        {
            return VigenereDecode(input, key, action, true);
        }

        /// <summary>
        /// Slovník pro morseovku
        /// </summary>
        private readonly static Dictionary<string, char> _morseDictionary = new()
        {
            { ".-", 'A' },
            { "-...", 'B' },
            { "-.-.", 'C' },
            { "-..", 'D' },
            { ".", 'E' },
            { "..-.", 'F' },
            { "--.", 'G' },
            { "....", 'H' },
            { "..", 'I' },
            { ".---", 'J' },
            { "-.-", 'K' },
            { ".-..", 'L' },
            { "--", 'M' },
            { "-.", 'N' },
            { "---", 'O' },
            { ".--.", 'P' },
            { "--.-", 'Q' },
            { ".-.", 'R' },
            { "...", 'S' },
            { "-", 'T' },
            { "..-", 'U' },
            { "...-", 'V' },
            { ".--", 'W' },
            { "-..-", 'X' },
            { "-.--", 'Y' },
            { "--..", 'Z' },
            { "-----", '0' },
            { ".----", '1' },
            { "..---", '2' },
            { "...--", '3' },
            { "....-", '4' },
            { ".....", '5' },
            { "-....", '6' },
            { "--...", '7' },
            { "---..", '8' },
            { "----.", '9' },
            { ".-.-.-", '.' },
            { "--..--", ',' },
            { "..--..", '?' },
            { ".----.", '\'' },
            { "-.-.--", '!' },
            { "-..-.", '/' },
            { "-.--.", '(' },
            { "-.--.-", ')' },
            { ".-...", '&' },
            { "---...", ':' },
            { "-.-.-.", ';' },
            { "-...-", '=' },
            { ".-.-.", '+' },
            { "-....-", '-' },
            { "..--.-", '_' },
            { ".-..-.", '"' },
            { "...-..-", '$' },
            { ".--.-.", '@' },
            { "/", ' ' }
        };

        /// <summary>
        /// Odšifruje text psaný morseovkou
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        public static string MorseDecode(string input)
        {
            RemoveDiacritics(ref input);
            string output = String.Empty;
            string[] letters = input.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            foreach (string letter in letters)
            {
                if (_morseDictionary.ContainsKey(letter))
                {
                    output += _morseDictionary[letter];
                }
                // je další větev zrovna u morseovky vhodná? 
                /*
                else
                {
                    output += letter;
                }
                */
            }
            return output;
        }

        /// <summary>
        /// Zašifruje text pomocí morseovky
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        public static string MorseEncode(string input, bool isSeparated = false)
        {
            RemoveDiacritics(ref input);
            string output = String.Empty;
            foreach (char ch in input.ToUpper())
            {
                if (_morseDictionary.ContainsValue(ch) && isSeparated)
                {
                    output += _morseDictionary.FirstOrDefault(x => x.Value == ch).Key + " ";
                }
                else if (_morseDictionary.ContainsValue(ch) && !isSeparated)
                {
                    output += _morseDictionary.FirstOrDefault(x => x.Value == ch).Key + " ";
                    output = output.Replace("/", String.Empty);
                }
                /*
                else
                {
                    output += ch;
                }
                */
            }
            return output;
        }

        /// <summary>
        /// Odšifruje text psaný ASCII šifrou
        /// </summary>
        /// <param name="input"></param>
        /// <param name="inputSystem"></param>
        /// <returns></returns>
        public static string AsciiDecode(string input, AsciiChoices inputSystem)
        {
            string output = String.Empty;
            string[] numbers = input.Split(' ', StringSplitOptions.RemoveEmptyEntries);

            switch (inputSystem)
            {
                case AsciiChoices.Desítkově:
                    foreach (string number in numbers)
                    {
                        if (int.TryParse(number, out int num))
                            output += (char)num;
                        else
                            output += number;
                    }
                    break;
                case AsciiChoices.Hexadecimálně:
                    foreach (string number in numbers)
                    {
                        if (int.TryParse(number, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out int num))
                            output += (char)num;
                        else
                            output += number;
                    }
                    break;
                case AsciiChoices.Binárně:
                    foreach (string number in numbers)
                    {
                        if (IsBinary(number))
                            output += (char)Convert.ToInt32(number, 2);
                        else
                            output += number;
                    }
                    break;
                case AsciiChoices.Osmičkově:
                    foreach (string number in numbers)
                    {
                        if (IsOctal(number))
                            output += (char)Convert.ToInt32(number, 8);
                        else
                            output += number;
                    }
                    break;
            }
            return output;
        }

        /// <summary>
        /// Zašifruje text pomocí ASCII šifry
        /// </summary>
        /// <param name="input"></param>
        /// <param name="outputSystem"></param>
        /// <returns></returns>
        public static string AsciiEncode(string input, AsciiChoices outputSystem)
        {
            RemoveDiacritics(ref input);
            string output = String.Empty;
            byte[] bytes = Encoding.ASCII.GetBytes(input);

            switch (outputSystem)
            {
                case AsciiChoices.Binárně:
                    foreach (byte b in bytes)
                    {
                        output += Convert.ToString(b, 2).PadLeft(8, '0') + " ";
                    }
                    break;
                case AsciiChoices.Desítkově:
                    foreach (byte b in bytes)
                    {
                        output += Convert.ToString(b, 10) + " ";
                    }
                    break;
                case AsciiChoices.Hexadecimálně:
                    foreach (byte b in bytes)
                    {
                        output += Convert.ToString(b, 16) + " ";
                    }
                    break;
                case AsciiChoices.Osmičkově:
                    foreach (byte b in bytes)
                    {
                        output += Convert.ToString(b, 8) + " ";
                    }
                    break;
            }

            return output.TrimEnd();
        }

        /// <summary>
        /// Vypočítá SHA hash ze zadaného textu
        /// </summary>
        /// <param name="input"></param>
        /// <param name="type"></param>
        /// <returns></returns>
        public static string HashSha(string input, ShaTypes type)
        {
            //RemoveDiacritics(ref input);
            byte[] bytes = Encoding.UTF8.GetBytes(input);
            string output = String.Empty;

            switch (type)
            {
                case ShaTypes.SHA1:
                    using (SHA1 sha1 = SHA1.Create())
                    {
                        byte[] hash = sha1.ComputeHash(bytes);
                        foreach (byte b in hash)
                        {
                            output += b.ToString("x2");
                        }
                    }
                    break;
                case ShaTypes.SHA256:
                    using (SHA256 sha256 = SHA256.Create())
                    {
                        byte[] hash = sha256.ComputeHash(bytes);
                        foreach (byte b in hash)
                        {
                            output += b.ToString("x2");
                        }
                    }
                    break;
                case ShaTypes.SHA384:
                    using (SHA384 sha384 = SHA384.Create())
                    {
                        byte[] hash = sha384.ComputeHash(bytes);
                        foreach (byte b in hash)
                        {
                            output += b.ToString("x2");
                        }
                    }
                    break;
                case ShaTypes.SHA512:
                    using (SHA512 sha512 = SHA512.Create())
                    {
                        byte[] hash = sha512.ComputeHash(bytes);
                        foreach (byte b in hash)
                        {
                            output += b.ToString("x2");
                        }
                    }
                    break;
            }
            return output;
        }

        /// <summary>
        /// Vypočítá MD5 hash ze zadaného textu
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        public static string HashMd5(string input)
        {
            //RemoveDiacritics(ref input);
            byte[] bytes = Encoding.UTF8.GetBytes(input);
            string output = String.Empty;
            using (MD5 md5 = MD5.Create())
            {
                byte[] hash = md5.ComputeHash(bytes);
                foreach (byte b in hash)
                {
                    output += b.ToString("x2");
                }
            }
            return output;
        }

        /// <summary>
        /// Generuje pár klíčů RSA (veřejný + soukromý)
        /// </summary>
        /// <param name="error"></param>
        /// <param name="bitSize"></param>
        /// <returns></returns>
        public static string[] GenerateKeyPairRsa(Action<string, string>? error, int bitSize)
        {
            string publicKey = String.Empty;
            string privateKey = String.Empty;
            using (RSACryptoServiceProvider rsa = new(bitSize))
            {
                try
                {
                    publicKey = Convert.ToBase64String(rsa.ExportRSAPublicKey());
                    privateKey = Convert.ToBase64String(rsa.ExportRSAPrivateKey());
                }
                catch { error?.Invoke("Nepodařilo se vygenerovat klíče (chybně zvolená velikost)", "Chyba"); }
                finally { rsa.PersistKeyInCsp = false; }
            }
            return new string[] { publicKey, privateKey };
        }

        /// <summary>
        /// Vypočítá RSA podpis ze zadaného textu v závislosti na veřejném klíči
        /// </summary>
        /// <param name="input"></param>
        /// <param name="publicKey"></param>
        /// <param name="error"></param>
        /// <returns></returns>
        public static string RsaEncode(string input, string publicKey, Action<string, string>? error)
        {
            string output = String.Empty;
            if (!String.IsNullOrEmpty(input) && !String.IsNullOrEmpty(publicKey))
            {
                using RSACryptoServiceProvider rsa = new();
                try
                {
                    rsa.ImportRSAPublicKey(Convert.FromBase64String(publicKey), out int bytesRead);
                    byte[] data = Encoding.Unicode.GetBytes(input);
                    byte[] cipher = rsa.Encrypt(data, false);
                    output = Convert.ToBase64String(cipher);
                }
                catch (FormatException)
                {
                    //error?.Invoke("Chyba formátování. Vstupní řetězec není ve formátu Base64.", "Chyba");
                }
                catch (CryptographicException)
                {
                    //error?.Invoke("Nastala chyba při provádění kryptografické operace.", "Chyba");
                }
                finally
                {
                    rsa.PersistKeyInCsp = false;
                }
            }
            return output;
        }

        /// <summary>
        /// Dešifruje RSA podpis z base64 řetězce v závislosti na soukromém klíči
        /// </summary>
        /// <param name="input"></param>
        /// <param name="privateKey"></param>
        /// <param name="error"></param>
        /// <returns></returns>
        public static string RsaDecode(string input, string privateKey, Action<string, string>? error)
        {
            string output = String.Empty;
            if (!String.IsNullOrEmpty(input) && !String.IsNullOrEmpty(privateKey))
            {
                using RSACryptoServiceProvider rsa = new();
                try
                {
                    rsa.ImportRSAPrivateKey(Convert.FromBase64String(privateKey), out int bytesRead);
                    byte[] dataBytes = Convert.FromBase64String(input);
                    byte[] plainText = rsa.Decrypt(dataBytes, false);
                    output = Encoding.Unicode.GetString(plainText);
                }
                catch (FormatException)
                {
                    //error?.Invoke("Chyba formátování. Vstupní řetězec není ve formátu Base64.", "Chyba");
                }
                catch (CryptographicException)
                {
                    //error?.Invoke("Nastala chyba při provádění kryptografické operace.", "Chyba");
                }
                finally
                {
                    rsa.PersistKeyInCsp = false;
                }
            }
            return output;
        }
    }
}