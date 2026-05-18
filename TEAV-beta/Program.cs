using System;
using System.Collections.Generic;
using System.IO;
using CommandLine;
using CommandLine.Text;
using TEAV.Core;
using TEAV.Modules;

namespace TEAV
{
    internal class Options
    {
        [Value(0, MetaName = "path", Required = true, HelpText = "File or directory to scan")]
        public string Path { get; set; }

        [Option('r', "recursive", Default = false, HelpText = "Scan directory recursively")]
        public bool Recursive { get; set; }

        [Option('v', "verbose", Default = false, HelpText = "Show all imports, not just suspicious")]
        public bool Verbose { get; set; }

        [Option("db", Default = null, HelpText = "Path to signature database (default: vvv.txt next to executable)")]
        public string DbPath { get; set; }

        [Option("min-score", Default = 70, HelpText = "Minimum heuristic score to report as a threat")]
        public int MinScore { get; set; }
    }

    internal class Program
    {
        private const string LINE = "------------------------------------------------------------";

        static int Main(string[] args)
        {
            var parser = new Parser(cfg => cfg.HelpWriter = null);
            var parsed = parser.ParseArguments<Options>(args);
            return parsed.MapResult(
                Run,
                _ =>
                {
                    var help = HelpText.AutoBuild(parsed, h =>
                    {
                        h.Heading   = "";
                        h.Copyright = "";
                        return h;
                    });
                    Console.Error.WriteLine(help);
                    return 1;
                }
            );
        }

        static int Run(Options opts)
        {
            Console.OutputEncoding = System.Text.Encoding.UTF8;

            string dbPath = opts.DbPath
                ?? Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "vvv.txt");

            PrintHeader();

            Console.Write($"  Loading signatures from: {dbPath} ... ");
            HashSet<string> db;
            try
            {
                db = SignatureScanner.LoadDatabase(dbPath);
                SetColor(ConsoleColor.Green);
                Console.WriteLine($"{db.Count:N0} loaded");
                ResetColor();
            }
            catch (Exception ex)
            {
                SetColor(ConsoleColor.Red);
                Console.WriteLine($"FAILED — {ex.Message}");
                ResetColor();
                db = new HashSet<string>();
            }

            Console.WriteLine();

            var results = new List<ScanResult>();
            bool isDir  = Directory.Exists(opts.Path);
            bool isFile = File.Exists(opts.Path);

            if (!isDir && !isFile)
            {
                SetColor(ConsoleColor.Red);
                Console.WriteLine($"  Error: path not found — {opts.Path}");
                ResetColor();
                return 2;
            }

            if (isFile)
            {
                var r = Scanner.ScanFile(opts.Path, db);
                PrintResult(r, opts);
                results.Add(r);
            }
            else
            {
                int index = 0;
                foreach (var r in Scanner.ScanDirectory(opts.Path, db, opts.Recursive))
                {
                    index++;
                    Console.Write($"\r  Scanning [{index}]: {TruncatePath(r.FilePath, 50)}   ");
                    results.Add(r);
                }
                Console.WriteLine();
                Console.WriteLine();

                foreach (var r in results)
                {
                    if (r.Verdict >= Verdict.Suspicious || r.SignatureMatch)
                        PrintResult(r, opts);
                }
            }

            PrintSummary(results);

            return 0;
        }

        static void PrintHeader()
        {
        }

        static void PrintResult(ScanResult r, Options opts)
        {
            Console.WriteLine();
            SetColor(ConsoleColor.White);
            Console.WriteLine($"  File : {r.FilePath}");
            Console.WriteLine($"  Size : {r.FileSize / 1024.0:F1} KB");
            ResetColor();
            Console.WriteLine(LINE);

            if (r.Error != null)
            {
                SetColor(ConsoleColor.Yellow);
                Console.WriteLine($"  [!] {r.Error}");
                ResetColor();
                return;
            }

            // блок 1 — сигнатуры
            Console.WriteLine("  [1] Signature Detection");
            Console.WriteLine($"      MD5    : {r.Md5}");
            Console.WriteLine($"      SHA1   : {r.Sha1}");
            Console.WriteLine($"      SHA256 : {r.Sha256}");

            if (r.SignatureMatch)
            {
                SetColor(ConsoleColor.Red);
                Console.WriteLine($"      Result : MATCH [{r.MatchedAlgorithm}] {r.MatchedHash}");
                ResetColor();
            }
            else
            {
                Console.WriteLine("      Result : No match");
            }

            if (r.SignatureMatch) goto verdict;

            // блок 2 — статика
            Console.WriteLine();
            Console.WriteLine("  [2] Static Analysis");

            if (!r.IsPe)
            {
                Console.WriteLine("      Not a PE file — static analysis skipped.");
                goto verdict;
            }

            string archStr = r.Is64Bit ? "PE32+" : "PE32";
            string sigStr  = r.SignatureValid ? "Valid" : (r.IsSigned ? "Invalid/Untrusted" : "Not signed");
            Console.WriteLine($"      Type      : {archStr} Executable");
            Console.WriteLine($"      Signature : {sigStr}");
            Console.WriteLine($"      Packer    : {(string.IsNullOrEmpty(r.PackerName) ? "None detected" : r.PackerName)}");
            Console.WriteLine($"      TLS       : {(r.HasTls ? "Yes (callbacks present)" : "No")}");
            Console.WriteLine($"      Imports   : {(r.HiddenImports ? "Dynamic/hidden (GetProcAddress)" : "Normal IAT")}");

            Console.WriteLine();
            Console.WriteLine("      Sections:");
            foreach (var sec in r.Sections)
            {
                string flags  = (sec.IsExecutable ? "X" : "-") + (sec.IsWritable ? "W" : "-");
                bool highEnt  = sec.IsExecutable && sec.Entropy > 6.5;

                if (highEnt) SetColor(ConsoleColor.Yellow);
                Console.WriteLine($"        {sec.Name,-12} entropy={sec.Entropy:F2}  [{flags}]{(highEnt ? "  *** HIGH ***" : "")}");
                if (highEnt) ResetColor();
            }

            if (r.SuspiciousImports.Count > 0)
            {
                Console.WriteLine();
                SetColor(ConsoleColor.Yellow);
                Console.WriteLine($"      Suspicious Imports ({r.SuspiciousImports.Count}):");
                foreach (var api in r.SuspiciousImports)
                    Console.WriteLine($"        [!] {api}");
                ResetColor();
            }
            else if (opts.Verbose)
            {
                Console.WriteLine("      No suspicious imports.");
            }

            if (r.SuspiciousStrings.Count > 0)
            {
                Console.WriteLine();
                SetColor(ConsoleColor.Yellow);
                Console.WriteLine($"      Suspicious Strings ({r.SuspiciousStrings.Count}):");
                foreach (var s in r.SuspiciousStrings)
                    Console.WriteLine($"        [!] {s}");
                ResetColor();
            }

            // блок 3 — эвристика
            Console.WriteLine();
            Console.WriteLine("  [3] Heuristic Analysis");

            if (r.HeuristicFlags.Count == 0)
            {
                Console.WriteLine("      No suspicious indicators.");
            }
            else
            {
                foreach (var flag in r.HeuristicFlags)
                    Console.WriteLine($"      +{flag.Score,-4} {flag.Description}");

                Console.WriteLine($"      {"",20}");
                Console.WriteLine($"      Score : {r.HeuristicScore}");
            }

            verdict:
            Console.WriteLine();
            Console.WriteLine(LINE);
            Console.Write("  VERDICT: ");
            PrintVerdict(r);
            Console.WriteLine(LINE);
        }

        static void PrintVerdict(ScanResult r)
        {
            switch (r.Verdict)
            {
                case Verdict.Malicious:
                    SetColor(ConsoleColor.Red);
                    Console.Write("*** MALICIOUS ***");
                    break;
                case Verdict.Suspicious:
                    SetColor(ConsoleColor.Yellow);
                    Console.Write("SUSPICIOUS");
                    break;
                case Verdict.PotentiallyUnwanted:
                    SetColor(ConsoleColor.DarkYellow);
                    Console.Write("POTENTIALLY UNWANTED");
                    break;
                default:
                    SetColor(ConsoleColor.Green);
                    Console.Write("CLEAN");
                    break;
            }
            ResetColor();

            if (r.SignatureMatch)
                Console.WriteLine($"  [Signature match — {r.MatchedAlgorithm}]");
            else if (r.Verdict != Verdict.Clean)
                Console.WriteLine($"  [Heuristic score: {r.HeuristicScore}]");
            else
                Console.WriteLine();
        }

        static void PrintSummary(List<ScanResult> results)
        {
            int total    = results.Count;
            int detected = 0;
            int errors   = 0;

            foreach (var r in results)
            {
                if (r.Verdict >= Verdict.Suspicious || r.SignatureMatch) detected++;
                if (r.Error != null) errors++;
            }

            Console.WriteLine();
            Console.WriteLine(LINE);
            Console.WriteLine($"  Scan complete — {total} file(s) scanned");

            if (detected > 0)
            {
                SetColor(ConsoleColor.Red);
                Console.WriteLine($"  Threats detected: {detected}");
                ResetColor();
            }
            else
            {
                SetColor(ConsoleColor.Green);
                Console.WriteLine("  No threats detected.");
                ResetColor();
            }

            if (errors > 0)
                Console.WriteLine($"  Errors: {errors}");

            Console.WriteLine(LINE);
            Console.WriteLine();
        }

        static string TruncatePath(string path, int max)
            => path.Length <= max ? path : "..." + path.Substring(path.Length - max + 3);

        static void SetColor(ConsoleColor c) => Console.ForegroundColor = c;
        static void ResetColor()             => Console.ResetColor();
    }
}
