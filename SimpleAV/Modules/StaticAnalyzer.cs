using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

namespace TEAV.Modules
{
    public class StaticResult
    {
        public PeInfo Pe { get; set; }
        public bool IsSigned { get; set; }
        public bool SignatureValid { get; set; }
        public string PackerName { get; set; }
        public bool HiddenImports { get; set; }
        public List<string> SuspiciousImports { get; set; } = new List<string>();
        public List<string> SuspiciousStrings { get; set; } = new List<string>();
    }

    public static class StaticAnalyzer
    {
        // словарь подозрительных апи с весами для эвристики
        // вес — насколько подозрительна эта штука, потом суммируем
        // важно: не завышать веса для апи которые юзает легитимный софт
        private static readonly Dictionary<string, int> DangerousApis =
            new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase)
        {
            // управление памятью — VirtualAlloc есть у всех, поэтому вес минимальный
            { "VirtualProtect",        10 },
            { "VirtualAlloc",           5 },
            // инжект в процесс — вот это уже серьёзно
            { "WriteProcessMemory",    35 },
            { "ReadProcessMemory",     10 },
            { "CreateRemoteThread",    35 },
            { "CreateRemoteThreadEx",  35 },
            // хуки — юзает accessibility и кейлоггеры, вес умеренный
            { "SetWindowsHookEx",      15 },
            { "SetWindowsHookExA",     15 },
            { "SetWindowsHookExW",     15 },
            // загрузка файлов из сети — специфично
            { "URLDownloadToFile",     30 },
            { "URLDownloadToFileA",    30 },
            { "URLDownloadToFileW",    30 },
            // запуск процессов — WinExec устаревший, легитимные не используют
            { "WinExec",               30 },
            // ShellExecute есть у каждого файл-менеджера и браузера — низкий вес
            { "ShellExecute",           8 },
            { "ShellExecuteA",          8 },
            { "ShellExecuteW",          8 },
            { "ShellExecuteEx",         8 },
            // OpenProcess — task manager, мониторинг — умеренно
            { "OpenProcess",           10 },
            // unmap секций — process hollowing, но .NET сам это делает — снизил
            { "NtUnmapViewOfSection",  25 },
            { "ZwUnmapViewOfSection",  25 },
            // антидебаг — IsDebuggerPresent юзают для лицензий тоже
            { "IsDebuggerPresent",     15 },
            { "CheckRemoteDebuggerPresent", 20 },
            { "NtQueryInformationProcess",  15 },
        };

        // имена секций которые оставляют упаковщики, типа UPX и компания
        private static readonly string[] PackerSectionNames =
        {
            "UPX0", "UPX1", "UPX2",
            "MPRESS1", "MPRESS2",
            ".packed", "ASPack", "ASPACK",
            "Themida", "WinLicense",
        };

        // байтовые маркеры упаковщиков — ищем прямо в теле файла
        private static readonly byte[][] PackerByteMarkers =
        {
            Encoding.ASCII.GetBytes("UPX!"),
            Encoding.ASCII.GetBytes("MPRESS"),
            Encoding.ASCII.GetBytes("FSG!"),
            Encoding.ASCII.GetBytes("MEW "),
            Encoding.ASCII.GetBytes("PEC2"),
        };

        // регулярки для поиска подозрительных строк в теле файла
        // костыль но рабочий — проверяем и ascii и unicode за один раз
        private static readonly (Regex rx, string label)[] StringPatterns =
        {
            (new Regex(@"powershell\s+-[Ee]nc",         RegexOptions.Compiled), "PowerShell encoded command (-enc)"),
            (new Regex(@"powershell\s+-[Ee]ncodedCommand", RegexOptions.Compiled), "PowerShell -EncodedCommand"),
            (new Regex(@"cmd(\.exe)?\s+/[cCkK]",        RegexOptions.Compiled), "cmd.exe /c execution"),
            (new Regex(@"rundll32",                      RegexOptions.Compiled | RegexOptions.IgnoreCase), "rundll32 usage"),
            (new Regex(@"reg\s+add",                     RegexOptions.Compiled | RegexOptions.IgnoreCase), "reg add (registry write)"),
            (new Regex(@"schtasks",                      RegexOptions.Compiled | RegexOptions.IgnoreCase), "schtasks (scheduled task)"),
            (new Regex(@"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", RegexOptions.Compiled), "Autorun registry key"),
            (new Regex(@"WScript\.Shell",                RegexOptions.Compiled), "WScript.Shell (scripting host)"),
            (new Regex(@"<script[^>]*language\s*=\s*[""']?(javascript|vbscript)", RegexOptions.Compiled | RegexOptions.IgnoreCase), "Embedded script tag (JS/VBS)"),
            (new Regex(@"ActiveXObject",                 RegexOptions.Compiled), "ActiveXObject creation"),
            // http url убрали — у каждого приложения с интернетом есть урлы, это мусорный флаг
            // ftp оставляем — встречается реже и более подозрительно
            (new Regex(@"\bftp://",                      RegexOptions.Compiled), "FTP URL"),
            // base64 паттерн — часто используется для передачи шеллкода или обфусцированных команд
            (new Regex(@"[A-Za-z0-9+/]{40,}={0,2}",    RegexOptions.Compiled), "Base64-like encoded data"),
        };

        // главная функция — запускает все проверки по очереди
        public static StaticResult Analyze(byte[] data, string filePath)
        {
            var result = new StaticResult();
            result.Pe = PeParser.Parse(data);

            if (!result.Pe.IsPe)
                return result;

            CheckSignature(filePath, result);
            DetectPacker(data, result);
            CheckHiddenImports(result);
            ClassifyImports(result);
            ScanStrings(data, result);

            return result;
        }

        // проверяем цифровую подпись через WinVerifyTrust — это виндовый апи
        // иногда тормозит если файл на сетевом диске, ничего не сделать пока
        private static void CheckSignature(string filePath, StaticResult result)
        {
            var fileInfo = new WinTrustFileInfo
            {
                cbStruct     = (uint)Marshal.SizeOf(typeof(WinTrustFileInfo)),
                pcwszFilePath = Marshal.StringToCoTaskMemUni(filePath),
            };

            IntPtr pFile = Marshal.AllocCoTaskMem(Marshal.SizeOf(typeof(WinTrustFileInfo)));
            Marshal.StructureToPtr(fileInfo, pFile, false);

            var trustData = new WinTrustData
            {
                cbStruct           = (uint)Marshal.SizeOf(typeof(WinTrustData)),
                dwUIChoice         = 2,  // WTD_UI_NONE — без окошек
                fdwRevocationChecks = 0, // WTD_REVOKE_NONE — не проверяем отзыв
                dwUnionChoice      = 1,  // WTD_CHOICE_FILE — проверяем файл
                pUnion             = pFile,
                dwStateAction      = 0,  // WTD_STATEACTION_IGNORE
            };

            IntPtr pData = Marshal.AllocCoTaskMem(Marshal.SizeOf(typeof(WinTrustData)));
            Marshal.StructureToPtr(trustData, pData, false);

            try
            {
                uint ret = NativeMethods.WinVerifyTrust(IntPtr.Zero, ref NativeMethods.WINTRUST_ACTION_GENERIC_VERIFY_V2, pData);

                // 0 = подпись валидная
                // 0x800B0100 = подписи вообще нет (TRUST_E_NOSIGNATURE)
                result.IsSigned      = ret != 0x800B0100;
                result.SignatureValid = ret == 0;
            }
            catch
            {
                // если апи недоступен — просто молча игнорируем
            }
            finally
            {
                Marshal.FreeCoTaskMem(fileInfo.pcwszFilePath);
                Marshal.FreeCoTaskMem(pFile);
                Marshal.FreeCoTaskMem(pData);
            }
        }

        // ищем упаковщик — сначала по именам секций, потом по байтам в файле
        private static void DetectPacker(byte[] data, StaticResult result)
        {
            // смотрим имена секций
            foreach (var sec in result.Pe.Sections)
            {
                foreach (var marker in PackerSectionNames)
                {
                    if (string.Equals(sec.Name, marker, StringComparison.OrdinalIgnoreCase))
                    {
                        result.PackerName = marker;
                        return;
                    }
                }
            }

            // если по секциям не нашли — ищем байтовые маркеры в первых 512кб
            int searchLen = Math.Min(data.Length, 524288);
            foreach (var marker in PackerByteMarkers)
            {
                if (IndexOf(data, marker, 0, searchLen) >= 0)
                {
                    result.PackerName = Encoding.ASCII.GetString(marker).TrimEnd();
                    return;
                }
            }
        }

        // проверяем скрыты ли импорты — это когда вирус не светит апи в таблице импортов
        private static void CheckHiddenImports(StaticResult result)
        {
            // если таблицы импортов вообще нет — это сразу подозрительно, типа упакован
            if (result.Pe.NoImportDirectory)
            {
                result.HiddenImports = true;
                return;
            }

            bool hasGetProcAddress = false, hasLoadLibrary = false;
            foreach (var imp in result.Pe.Imports)
            {
                if (imp.Function.StartsWith("GetProcAddress", StringComparison.OrdinalIgnoreCase))
                    hasGetProcAddress = true;
                if (imp.Function.StartsWith("LoadLibrary", StringComparison.OrdinalIgnoreCase))
                    hasLoadLibrary = true;
            }
            // если используют GetProcAddress + LoadLibrary вместе — значит грузят апи в рантайме и прячут импорты
            result.HiddenImports = hasGetProcAddress && hasLoadLibrary;
        }

        // пробегаем по импортам и отмечаем какие из них подозрительные
        private static void ClassifyImports(StaticResult result)
        {
            foreach (var imp in result.Pe.Imports)
            {
                if (DangerousApis.ContainsKey(imp.Function))
                    result.SuspiciousImports.Add(imp.Function);
            }
        }

        // ищем подозрительные строки в теле файла — и ascii и unicode
        private static void ScanStrings(byte[] data, StaticResult result)
        {
            string ascii   = ExtractAscii(data);
            string unicode = ExtractUnicode(data);
            string combined = ascii + "\n" + unicode;

            var seen = new HashSet<string>();
            foreach (var (rx, label) in StringPatterns)
            {
                if (rx.IsMatch(combined) && seen.Add(label))
                    result.SuspiciousStrings.Add(label);
            }
        }

        // вытаскиваем ascii строки длиной от 5 символов
        // считает неправильно если в данных есть мусор между нормальными строками — иногда пропускает, надо будет переписать
        private static string ExtractAscii(byte[] data)
        {
            var sb = new StringBuilder(data.Length / 4);
            int run = 0;
            int start = 0;
            for (int i = 0; i < data.Length; i++)
            {
                byte b = data[i];
                if (b >= 0x20 && b <= 0x7E)
                {
                    if (run == 0) start = i;
                    run++;
                }
                else
                {
                    if (run >= 5)
                    {
                        sb.Append(Encoding.ASCII.GetString(data, start, run));
                        sb.Append('\n');
                    }
                    run = 0;
                }
            }
            return sb.ToString();
        }

        // то же самое но для utf-16le строк — виндовые программы часто их используют
        private static string ExtractUnicode(byte[] data)
        {
            var sb = new StringBuilder();
            int run = 0;
            int start = 0;
            for (int i = 0; i + 1 < data.Length; i += 2)
            {
                ushort c = BitConverter.ToUInt16(data, i);
                if (c >= 0x20 && c <= 0x7E)
                {
                    if (run == 0) start = i;
                    run++;
                }
                else
                {
                    if (run >= 5)
                    {
                        sb.Append(Encoding.Unicode.GetString(data, start, run * 2));
                        sb.Append('\n');
                    }
                    run = 0;
                }
            }
            return sb.ToString();
        }

        // boyer-moore-horspool для поиска байтового паттерна — быстрее наивного поиска
        private static int IndexOf(byte[] haystack, byte[] needle, int start, int length)
        {
            if (needle.Length == 0) return start;
            int end = Math.Min(start + length, haystack.Length) - needle.Length;

            int[] skip = new int[256];
            for (int i = 0; i < 256; i++) skip[i] = needle.Length;
            for (int i = 0; i < needle.Length - 1; i++) skip[needle[i]] = needle.Length - 1 - i;

            for (int i = start; i <= end; )
            {
                int j = needle.Length - 1;
                while (j >= 0 && haystack[i + j] == needle[j]) j--;
                if (j < 0) return i;
                i += skip[haystack[i + needle.Length - 1]];
            }
            return -1;
        }

        // возвращаем вес апи для эвристики, 0 если апи не подозрительный
        public static int GetApiWeight(string functionName)
        {
            return DangerousApis.TryGetValue(functionName, out int w) ? w : 0;
        }
    }

    // структуры для p/invoke WinVerifyTrust — скопировал из msdn и немного подправил

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct WinTrustFileInfo
    {
        public uint    cbStruct;
        public IntPtr  pcwszFilePath;
        public IntPtr  hFile;
        public IntPtr  pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct WinTrustData
    {
        public uint   cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint   dwUIChoice;
        public uint   fdwRevocationChecks;
        public uint   dwUnionChoice;
        public IntPtr pUnion;
        public uint   dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint   dwProvFlags;
        public uint   dwUIContext;
    }

    internal static class NativeMethods
    {
        // guid для проверки authenticode подписи — захардкожен, так надо
        public static Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 =
            new Guid(0x00AAC56B, 0xCD44, 0x11D0, 0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE);

        [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = false, CharSet = CharSet.Unicode)]
        public static extern uint WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID, IntPtr pWVTData);
    }
}
