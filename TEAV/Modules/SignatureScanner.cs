using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace TEAV.Modules
{
    public class SignatureMatch
    {
        public string Algorithm { get; set; }
        public string Hash { get; set; }
    }

    public static class SignatureScanner
    {
        // грузим все хэши из файла в HashSet чтоб потом быстро искать
        // формат строки: "номер\tхэш" или просто "хэш" — оба варианта норм
        public static HashSet<string> LoadDatabase(string dbPath)
        {
            // заранее выделяем место под миллион с хвостиком записей чтоб не ресайзить каждый раз
            var set = new HashSet<string>(1200000, StringComparer.OrdinalIgnoreCase);

            if (!File.Exists(dbPath))
                return set;

            foreach (var line in File.ReadLines(dbPath, Encoding.UTF8))
            {
                if (string.IsNullOrWhiteSpace(line))
                    continue;

                var tab = line.IndexOf('\t');
                var hash = tab >= 0 ? line.Substring(tab + 1).Trim() : line.Trim();

                if (hash.Length > 0)
                    set.Add(hash.ToLowerInvariant());
            }

            return set;
        }

        // считаем сразу три хэша за один проход по файлу — типа оптимизация
        // не до конца рабочая хрень если файл открыт другой программой — иногда кидает исключение, потом разберусь
        public static (string md5, string sha1, string sha256) ComputeHashes(string filePath)
        {
            using (var md5 = MD5.Create())
            using (var sha1 = SHA1.Create())
            using (var sha256 = SHA256.Create())
            using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 65536))
            {
                var buffer = new byte[65536];
                int read;
                while ((read = fs.Read(buffer, 0, buffer.Length)) > 0)
                {
                    md5.TransformBlock(buffer, 0, read, null, 0);
                    sha1.TransformBlock(buffer, 0, read, null, 0);
                    sha256.TransformBlock(buffer, 0, read, null, 0);
                }

                md5.TransformFinalBlock(buffer, 0, 0);
                sha1.TransformFinalBlock(buffer, 0, 0);
                sha256.TransformFinalBlock(buffer, 0, 0);

                return (
                    HashToHex(md5.Hash),
                    HashToHex(sha1.Hash),
                    HashToHex(sha256.Hash)
                );
            }
        }

        // просто ищем совпадение в базе, сначала md5 потом sha1 потом sha256
        public static SignatureMatch Check(string md5, string sha1, string sha256, HashSet<string> db)
        {
            if (db.Contains(md5))
                return new SignatureMatch { Algorithm = "MD5", Hash = md5 };

            if (db.Contains(sha1))
                return new SignatureMatch { Algorithm = "SHA1", Hash = sha1 };

            if (db.Contains(sha256))
                return new SignatureMatch { Algorithm = "SHA256", Hash = sha256 };

            return null;
        }

        // переводим массив байтов в hex строку, вот и всё
        private static string HashToHex(byte[] bytes)
        {
            var sb = new StringBuilder(bytes.Length * 2);
            foreach (var b in bytes)
                sb.AppendFormat("{0:x2}", b);
            return sb.ToString();
        }
    }
}
