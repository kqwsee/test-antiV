using System;
using System.IO;
using Newtonsoft.Json;

namespace TEAV.Core
{
    public static class Quarantine
    {
        // ключ для xor — просто чтоб файл нельзя было случайно запустить, не криптография
        private const byte XOR_KEY = 0xAA;

        private static string _quarantineDir;

        // инициализируем папку карантина, создаём если нет
        public static void Init(string baseDir)
        {
            _quarantineDir = Path.Combine(baseDir, "quarantine");
            Directory.CreateDirectory(_quarantineDir);
        }

        // перемещаем файл в карантин — xor шифруем и сохраняем метадату рядом
        // не до конца рабочая штука если карантин на другом диске чем файл — Move не работает, только Copy+Delete
        public static bool MoveToQuarantine(ScanResult result)
        {
            try
            {
                string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
                string safeName  = SanitizeFileName(Path.GetFileName(result.FilePath));
                string baseName  = $"{safeName}_{timestamp}";

                string quarFile  = Path.Combine(_quarantineDir, baseName + ".quar");
                string metaFile  = Path.Combine(_quarantineDir, baseName + ".meta");

                // xor шифруем и пишем — файл теперь не запустится случайно
                byte[] original = File.ReadAllBytes(result.FilePath);
                byte[] encoded  = XorTransform(original);
                File.WriteAllBytes(quarFile, encoded);

                // json метадата чтоб потом знать откуда файл и почему задетекчен
                var meta = new
                {
                    OriginalPath      = result.FilePath,
                    FileName          = Path.GetFileName(result.FilePath),
                    FileSize          = result.FileSize,
                    QuarantinedAt     = DateTime.Now.ToString("o"),
                    Md5               = result.Md5,
                    Sha256            = result.Sha256,
                    Verdict           = result.Verdict.ToString(),
                    DetectionSource   = result.DetectionSource.ToString(),
                    HeuristicScore    = result.HeuristicScore,
                    SignatureMatch    = result.SignatureMatch ? result.MatchedHash : null,
                    SuspiciousImports = result.SuspiciousImports,
                    SuspiciousStrings = result.SuspiciousStrings,
                    PackerName        = result.PackerName,
                };

                File.WriteAllText(metaFile, JsonConvert.SerializeObject(meta, Formatting.Indented));

                // удаляем оригинал после успешного копирования в карантин
                File.Delete(result.FilePath);
                return true;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"  [Quarantine error] {ex.Message}");
                return false;
            }
        }

        // восстанавливаем файл из карантина обратно на место
        public static bool Restore(string quarFile)
        {
            string metaFile = Path.ChangeExtension(quarFile, ".meta");
            if (!File.Exists(metaFile))
            {
                Console.Error.WriteLine("  [Restore error] Metadata file not found.");
                return false;
            }

            try
            {
                var meta = JsonConvert.DeserializeObject<QuarantineMeta>(File.ReadAllText(metaFile));
                string originalPath = meta.OriginalPath;

                byte[] encoded  = File.ReadAllBytes(quarFile);
                byte[] original = XorTransform(encoded); // xor симметричный — та же функция для декодирования
                File.WriteAllBytes(originalPath, original);

                File.Delete(quarFile);
                File.Delete(metaFile);
                return true;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"  [Restore error] {ex.Message}");
                return false;
            }
        }

        // просто удаляем файл, ничего сложного
        public static bool DeleteFile(string filePath)
        {
            try
            {
                File.Delete(filePath);
                return true;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"  [Delete error] {ex.Message}");
                return false;
            }
        }

        // xor это своя инверсия — один и тот же метод и для шифрования и для расшифровки
        private static byte[] XorTransform(byte[] data)
        {
            byte[] out_ = new byte[data.Length];
            for (int i = 0; i < data.Length; i++)
                out_[i] = (byte)(data[i] ^ XOR_KEY);
            return out_;
        }

        // чистим имя файла от запрещённых символов чтоб нормально сохранить
        // вроде работает но не проверял все краевые случаи с юникодными именами файлов
        private static string SanitizeFileName(string name)
        {
            foreach (char c in Path.GetInvalidFileNameChars())
                name = name.Replace(c, '_');
            return name;
        }
    }

    // минимальный класс для десериализации метадаты — нам нужен только путь
    internal class QuarantineMeta
    {
        public string OriginalPath { get; set; }
    }
}
