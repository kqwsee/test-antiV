using System;
using System.Collections.Generic;
using System.IO;
using TEAV.Modules;

namespace TEAV.Core
{
    public static class Scanner
    {
        private const long MAX_FILE_SIZE = 200 * 1024 * 1024;
        
        
        public static ScanResult ScanFile(string filePath, HashSet<string> signatures)
        {
            var result = new ScanResult { FilePath = filePath };

            try
            {
                var fi = new FileInfo(filePath);
                result.FileSize = fi.Length;

                if (fi.Length > MAX_FILE_SIZE)
                {
                    result.Error = "File too large (> 200 MB), skipped.";
                    return result;
                }

                // сигнатурное обнаружение, считаем хэши и ищем в базе
                var (md5, sha1, sha256) = SignatureScanner.ComputeHashes(filePath);
                result.Sha256 = sha256;

                var match = SignatureScanner.Check(md5, sha1, sha256, signatures);
                if (match != null)
                {
                    result.SignatureMatch   = true;
                    result.MatchedHash      = match.Hash;
                    result.MatchedAlgorithm = match.Algorithm;
                    result.Verdict          = Verdict.Malicious;
                    result.DetectionSource  = DetectionSource.Signature;
                    // нашли по сигнатуре 
                    return result;
                }

                // этап 2 — статический анализ pe файла
                byte[] data = File.ReadAllBytes(filePath);
                var staticResult = StaticAnalyzer.Analyze(data, filePath);

                result.IsPe              = staticResult.Pe.IsPe;
                result.Is64Bit           = staticResult.Pe.Is64Bit;
                result.IsSigned          = staticResult.IsSigned;
                result.SignatureValid     = staticResult.SignatureValid;
                result.PackerName        = staticResult.PackerName;
                result.HasTls            = staticResult.Pe.HasTls;
                result.HiddenImports     = staticResult.HiddenImports;
                result.SuspiciousImports = staticResult.SuspiciousImports;
                result.SuspiciousStrings = staticResult.SuspiciousStrings;
                result.Sections          = staticResult.Pe.Sections;

                if (!staticResult.Pe.IsPe)
                {
                    result.Verdict = Verdict.Clean; // не pe файл — чистый, нечего анализировать
                    return result;
                }

                // этап 3 — эвристика, считаем баллы и выносим вердикт
                var heuristic = HeuristicEngine.Evaluate(staticResult);
                result.HeuristicScore  = heuristic.Score;
                result.HeuristicFlags  = heuristic.Flags;
                result.Verdict         = heuristic.Verdict;
                result.DetectionSource = DetectionSource.Heuristic;
            }
            catch (UnauthorizedAccessException)
            {
                result.Error = "Access denied.";
            }
            catch (Exception ex)
            {
                result.Error = ex.Message;
            }

            return result;
        }

        // сканируем всю папку, если recursive то и подпапки тоже
        // вроде работает но не тестировал на папках с симлинками, может зациклиться
        public static IEnumerable<ScanResult> ScanDirectory(string dirPath, HashSet<string> signatures, bool recursive)
        {
            var option = recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly;

            string[] files = null;
            string dirError = null;
            try
            {
                files = Directory.GetFiles(dirPath, "*.*", option);
            }
            catch (Exception ex)
            {
                dirError = ex.Message;
            }

            if (dirError != null)
            {
                yield return new ScanResult { FilePath = dirPath, Error = dirError };
                yield break;
            }

            foreach (var file in files)
                yield return ScanFile(file, signatures);
        }
    }
}
