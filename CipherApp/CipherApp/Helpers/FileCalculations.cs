using CipherApp.Models;
using Force.Crc32;
using System;
using System.IO;
using System.Security.Cryptography;

namespace CipherApp.Helpers
{
    public static class FileCalculations
    {
        /// <summary>
        /// Vrací velikost souboru
        /// </summary>
        /// <param name="path"></param>
        /// <returns></returns>
        public static long GetFileSize(string path)
        {
            try
            {
                return new FileInfo(path).Length;
            }
            catch
            {
                return 0;
            }
        }

        /// <summary>
        /// Vypočítá SHA hash ze souboru
        /// </summary>
        /// <param name="path"></param>
        /// <param name="type"></param>
        /// <returns></returns>
        public static string CalculateSha(string path, ShaTypes type)
        {
            try
            {
                using var stream = new FileStream(path, FileMode.Open);
                switch (type)
                {
                    case ShaTypes.SHA1:
                        using (SHA1 sha1 = SHA1.Create())
                        {
                            return BitConverter.ToString(sha1.ComputeHash(stream)).Replace("-", "").ToLowerInvariant();
                        }
                    case ShaTypes.SHA256:
                        using (SHA256 sha256 = SHA256.Create())
                        {
                            return BitConverter.ToString(sha256.ComputeHash(stream)).Replace("-", "").ToLowerInvariant();
                        }
                    case ShaTypes.SHA384:
                        using (SHA384 sha384 = SHA384.Create())
                        {
                            return BitConverter.ToString(sha384.ComputeHash(stream)).Replace("-", "").ToLowerInvariant();
                        }
                    case ShaTypes.SHA512:
                        using (SHA512 sha512 = SHA512.Create())
                        {
                            return BitConverter.ToString(sha512.ComputeHash(stream)).Replace("-", "").ToLowerInvariant();
                        }
                    default: return String.Empty;
                }
            }
            catch (Exception) { throw new FileLoadException(); }
        }

        /// <summary>
        /// Vypočítá MD5 hash ze souboru
        /// </summary>
        /// <param name="path"></param>
        /// <returns></returns>
        /// <exception cref="FileLoadException"></exception>
        public static string CalculateMd5(string path)
        {
            try
            {
                using var stream = new FileStream(path, FileMode.Open);
                using MD5 md5 = MD5.Create();
                return BitConverter.ToString(md5.ComputeHash(stream)).Replace("-", "").ToLowerInvariant();
            }
            catch (Exception) { throw new FileLoadException(); }
        }

        /// <summary>
        /// Vypočítá CRC32 hash ze souboru
        /// </summary>
        /// <param name="path"></param>
        /// <returns></returns>
        /// <exception cref="FileLoadException"></exception>
        public static string CalculateCrc32(string path)
        {
            try
            {
                using var stream = new FileStream(path, FileMode.Open);
                var crc32 = new Crc32Algorithm();
                return BitConverter.ToString(crc32.ComputeHash(stream)).Replace("-", "").ToLowerInvariant();
            }
            catch (Exception) { throw new FileLoadException(); }
        }
    }
}
