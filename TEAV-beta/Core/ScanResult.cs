using System.Collections.Generic;

namespace TEAV.Core
{
    public enum Verdict
    {
        Clean,
        PotentiallyUnwanted,
        Suspicious,
        Malicious
    }

    public enum DetectionSource
    {
        Signature,
        Heuristic
    }

    public class HeuristicFlag
    {
        public int Score { get; set; }
        public string Description { get; set; }
    }

    public class ScanResult
    {
        public string FilePath { get; set; }
        public long FileSize { get; set; }

        // данные сигнатурного анализа — хэши и совпадение
        public string Md5 { get; set; }
        public string Sha1 { get; set; }
        public string Sha256 { get; set; }
        public bool SignatureMatch { get; set; }
        public string MatchedHash { get; set; }
        public string MatchedAlgorithm { get; set; }

        // данные статического анализа — что нашли в pe файле
        public bool IsPe { get; set; }
        public bool Is64Bit { get; set; }
        public bool IsSigned { get; set; }
        public bool SignatureValid { get; set; }
        public string PackerName { get; set; }
        public bool HasTls { get; set; }
        public bool HiddenImports { get; set; }
        public List<string> SuspiciousImports { get; set; } = new List<string>();
        public List<string> SuspiciousStrings { get; set; } = new List<string>();
        public List<SectionEntry> Sections { get; set; } = new List<SectionEntry>();

        // результаты эвристики — баллы и флаги
        public int HeuristicScore { get; set; }
        public List<HeuristicFlag> HeuristicFlags { get; set; } = new List<HeuristicFlag>();

        // итоговый вердикт и откуда он взялся
        public Verdict Verdict { get; set; }
        public DetectionSource DetectionSource { get; set; }
        public string Error { get; set; }
    }

    public class SectionEntry
    {
        public string Name { get; set; }
        public double Entropy { get; set; }
        public bool IsExecutable { get; set; }
        public bool IsWritable { get; set; }
        public uint VirtualSize { get; set; }
        public uint RawSize { get; set; }
    }
}
