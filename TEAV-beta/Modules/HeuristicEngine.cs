using System.Collections.Generic;
using TEAV.Core;

namespace TEAV.Modules
{
    public class HeuristicResult
    {
        public int Score { get; set; }
        public Verdict Verdict { get; set; }
        public List<HeuristicFlag> Flags { get; set; } = new List<HeuristicFlag>();
    }

    public static class HeuristicEngine
    {
        // пороги подняты — иначе половина легитимного фриварного софта попадала в PUP
        private const int THRESHOLD_PUP        = 40;
        private const int THRESHOLD_SUSPICIOUS = 80;
        private const int THRESHOLD_MALICIOUS  = 120;

        // 6.5 было слишком низко — сжатые ресурсы легитимных приложений легко его пересекают
        private const double ENTROPY_HIGH = 7.2;

        // главная функция — считает баллы и выносит вердикт
        public static HeuristicResult Evaluate(StaticResult s)
        {
            var result = new HeuristicResult();
            var flags  = result.Flags;
            int score  = 0;

            // если файл вообще не pe — чистый, нечего анализировать
            if (!s.Pe.IsPe)
            {
                result.Verdict = Verdict.Clean;
                return result;
            }

            // тут храним какие апи уже посчитали чтоб не добавлять баллы дважды
            var counted = new HashSet<string>();

            // +10 если файл не подписан — снизили с 20, это слишком распространено у легитимного фриваре
            if (!s.SignatureValid)
            {
                score += 10;
                flags.Add(new HeuristicFlag { Score = 10, Description = "File is not digitally signed" });
            }

            // +20 если энтропия исполняемой секции высокая — порог 7.2 чтоб не флагать сжатые ресурсы
            foreach (var sec in s.Pe.Sections)
            {
                if (sec.IsExecutable && sec.Entropy > ENTROPY_HIGH)
                {
                    score += 20;
                    flags.Add(new HeuristicFlag
                    {
                        Score = 20,
                        Description = $"High entropy ({sec.Entropy:F2}) in executable section '{sec.Name}'"
                    });
                    break; // считаем только один раз даже если секций несколько
                }
            }

            // +35 за секцию которая одновременно W и X — легитимные компиляторы так не делают
            // это классический признак шеллкода или инжекта
            foreach (var sec in s.Pe.Sections)
            {
                if (sec.IsExecutable && sec.IsWritable)
                {
                    score += 35;
                    flags.Add(new HeuristicFlag
                    {
                        Score = 35,
                        Description = $"Section '{sec.Name}' is both writable and executable (shellcode indicator)"
                    });
                    break;
                }
            }

            // +55 за комбо инжекта — было +30 что меньше чем по отдельности, это было неправильно
            // комбо WPM+CRT это конкретный паттерн инжекции, должен давать больше индивидуальных весов
            bool hasWPM = s.SuspiciousImports.Contains("WriteProcessMemory");
            bool hasCRT = s.SuspiciousImports.Contains("CreateRemoteThread") ||
                          s.SuspiciousImports.Contains("CreateRemoteThreadEx");
            if (hasWPM && hasCRT)
            {
                score += 55;
                flags.Add(new HeuristicFlag { Score = 55, Description = "WriteProcessMemory + CreateRemoteThread — process injection" });
                counted.Add("WriteProcessMemory");
                counted.Add("CreateRemoteThread");
                counted.Add("CreateRemoteThreadEx");
            }

            // +30 за закодированные команды powershell — подняли, это очень специфично для малвари
            if (s.SuspiciousStrings.Contains("PowerShell encoded command (-enc)") ||
                s.SuspiciousStrings.Contains("PowerShell -EncodedCommand"))
            {
                score += 30;
                flags.Add(new HeuristicFlag { Score = 30, Description = "Contains PowerShell encoded command" });
            }

            // +20 за ключ автозапуска — подняли с 15, персистентность это серьёзно
            if (s.SuspiciousStrings.Contains("Autorun registry key"))
            {
                score += 20;
                flags.Add(new HeuristicFlag { Score = 20, Description = "References autorun registry key (persistence)" });
            }

            // +20 за reg add / schtasks — снизили с 40, много легитимных установщиков это делают
            if (s.SuspiciousStrings.Contains("reg add (registry write)") ||
                s.SuspiciousStrings.Contains("schtasks (scheduled task)"))
            {
                score += 20;
                flags.Add(new HeuristicFlag { Score = 20, Description = "System persistence via reg add / schtasks" });
            }

            // +20 если обнаружен упаковщик — снизили с 30, UPX юзают и легитимные приложения
            if (!string.IsNullOrEmpty(s.PackerName))
            {
                score += 20;
                flags.Add(new HeuristicFlag { Score = 20, Description = $"Packer detected: {s.PackerName}" });
            }

            // +30 за скрытые импорты — подняли с 25, это специфично для малвари
            if (s.HiddenImports)
            {
                score += 30;
                flags.Add(new HeuristicFlag { Score = 30, Description = "Dynamic import hiding (GetProcAddress + LoadLibraryA)" });
            }

            // +20 за tls колбэки — выполняются до точки входа, антидебаг техника
            if (s.Pe.HasTls)
            {
                score += 20;
                flags.Add(new HeuristicFlag { Score = 20, Description = "TLS callbacks present (executes before entry point)" });
            }

            // добавляем баллы за оставшиеся подозрительные апи которые ещё не посчитали
            foreach (var api in s.SuspiciousImports)
            {
                if (counted.Contains(api)) continue;

                int w = StaticAnalyzer.GetApiWeight(api);
                if (w > 0)
                {
                    score += w;
                    flags.Add(new HeuristicFlag { Score = w, Description = $"Suspicious import: {api}" });
                    counted.Add(api);
                }
            }

            // веса для строковых паттернов
            // cmd.exe снизили — очень распространено у легитимных
            // base64 добавили — типичный способ передачи шеллкода
            var stringWeights = new Dictionary<string, int>
            {
                { "cmd.exe /c execution",             8  },
                { "rundll32 usage",                   15 },
                { "WScript.Shell (scripting host)",   20 },
                { "Embedded script tag (JS/VBS)",     25 },
                { "ActiveXObject creation",           20 },
                { "FTP URL",                          15 },
                { "Base64-like encoded data",         15 },
            };

            // эти строки уже посчитали выше — не трогаем
            var alreadyCounted = new HashSet<string>
            {
                "PowerShell encoded command (-enc)",
                "PowerShell -EncodedCommand",
                "Autorun registry key",
                "reg add (registry write)",
                "schtasks (scheduled task)",
            };

            foreach (var label in s.SuspiciousStrings)
            {
                if (alreadyCounted.Contains(label)) continue;
                if (stringWeights.TryGetValue(label, out int w))
                {
                    score += w;
                    flags.Add(new HeuristicFlag { Score = w, Description = label });
                    alreadyCounted.Add(label);
                }
            }

            result.Score = score;
            result.Verdict = score >= THRESHOLD_MALICIOUS  ? Verdict.Malicious
                           : score >= THRESHOLD_SUSPICIOUS ? Verdict.Suspicious
                           : score >= THRESHOLD_PUP        ? Verdict.PotentiallyUnwanted
                           :                                 Verdict.Clean;
            return result;
        }
    }
}
