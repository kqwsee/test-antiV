using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using TEAV.Core;

namespace TEAV.Modules
{
    public class PeInfo
    {
        public bool IsPe { get; set; }
        public bool Is64Bit { get; set; }
        public List<SectionEntry> Sections { get; set; } = new List<SectionEntry>();
        public List<ImportEntry> Imports { get; set; } = new List<ImportEntry>();
        public bool HasTls { get; set; }
        public bool NoImportDirectory { get; set; }
        public string ParseError { get; set; }
    }

    public class ImportEntry
    {
        public string Dll { get; set; }
        public string Function { get; set; }
    }

    // внутренняя хрень — хранит виртуальный адрес секции, он нужен чтоб rva переводить в offset
    // снаружи его не отдаём, там он не нужен
    internal class RawSection
    {
        public string Name;
        public uint VirtualAddress;
        public uint VirtualSize;
        public uint RawOffset;
        public uint RawSize;
        public uint Characteristics;
        public double Entropy;
    }

    public static class PeParser
    {
        private const ushort MZ     = 0x5A4D;
        private const uint   PE_SIG = 0x00004550;
        private const ushort OPT_32 = 0x010B;
        private const ushort OPT_64 = 0x020B;

        // смещение до DataDirectory[0] от начала Optional Header
        // для PE32 это 96 байт, для PE32+ это 112 — взял из спеки MSDN, проверил вручную
        private const int DIR_BASE_32 = 96;
        private const int DIR_BASE_64 = 112;

        // главная публичная функция, просто вызывает внутреннюю и ловит исключения
        public static PeInfo Parse(byte[] data)
        {
            var info = new PeInfo();
            try   { ParseInternal(data, info); }
            catch (Exception ex) { info.ParseError = ex.Message; }
            return info;
        }

        // тут ваще всё и происходит — парсим заголовки pe файла
        // вроде работает но на сильно кривых файлах иногда багует, try/catch спасает
        private static void ParseInternal(byte[] data, PeInfo info)
        {
            if (data.Length < 64) return;

            using (var ms = new MemoryStream(data))
            using (var r  = new BinaryReader(ms))
            {
                // проверяем dos заголовок — ищем MZ в начале
                if (r.ReadUInt16() != MZ) return;
                ms.Seek(0x3C, SeekOrigin.Begin);
                long peOff = r.ReadUInt32();
                if (peOff + 24 >= data.Length) return;

                // прыгаем к pe сигнатуре и coff заголовку
                ms.Seek(peOff, SeekOrigin.Begin);
                if (r.ReadUInt32() != PE_SIG) return;
                info.IsPe = true;

                r.ReadUInt16();                     // тип машины — нам не нужен
                ushort numSections = r.ReadUInt16();
                r.ReadUInt32();                     // дата сборки — пропускаем
                r.ReadUInt32();                     // символьная таблица — тоже пропускаем
                r.ReadUInt32();                     // количество символов
                ushort optSize = r.ReadUInt16();
                r.ReadUInt16();                     // флаги файла

                long optStart = ms.Position;

                // читаем optional header — тут определяем 32 или 64 бит
                ushort magic = r.ReadUInt16();
                if (magic != OPT_32 && magic != OPT_64) return;
                bool is64 = magic == OPT_64;
                info.Is64Bit = is64;

                int dirBase = is64 ? DIR_BASE_64 : DIR_BASE_32;

                // DataDirectory[1] это таблица импортов, каждая запись 8 байт (rva + size)
                ms.Seek(optStart + dirBase + 1 * 8, SeekOrigin.Begin);
                uint importRva = r.ReadUInt32();
                r.ReadUInt32(); // размер — не нужен

                // DataDirectory[9] это tls директория
                ms.Seek(optStart + dirBase + 9 * 8, SeekOrigin.Begin);
                uint tlsRva  = r.ReadUInt32();
                info.HasTls  = tlsRva != 0;

                // секции идут сразу после optional header
                ms.Seek(optStart + optSize, SeekOrigin.Begin);
                var sections = ReadSections(r, numSections, data);

                // копируем во внешний тип, виртуальный адрес наружу не отдаём
                foreach (var s in sections)
                    info.Sections.Add(new SectionEntry
                    {
                        Name         = s.Name,
                        VirtualSize  = s.VirtualSize,
                        RawSize      = s.RawSize,
                        Entropy      = s.Entropy,
                        IsExecutable = (s.Characteristics & 0x20000000) != 0,
                        IsWritable   = (s.Characteristics & 0x80000000) != 0,
                    });

                if (importRva == 0)
                    info.NoImportDirectory = true; // нет таблицы импортов — подозрительно, типа упакован
                else
                {
                    uint off = Rva2Off(importRva, sections);
                    if (off != 0)
                        ReadImports(data, off, sections, is64, info.Imports);
                }
            }
        }

        // читаем все секции файла и считаем энтропию каждой
        private static List<RawSection> ReadSections(BinaryReader r, ushort count, byte[] data)
        {
            var list = new List<RawSection>(count);
            for (int i = 0; i < count; i++)
            {
                string name = Encoding.ASCII.GetString(r.ReadBytes(8)).TrimEnd('\0');
                uint vSize  = r.ReadUInt32();
                uint vAddr  = r.ReadUInt32();
                uint rSize  = r.ReadUInt32();
                uint rOff   = r.ReadUInt32();
                r.ReadBytes(12);                // пропускаем релоки и номера строк
                uint chars  = r.ReadUInt32();

                double entropy = 0;
                if (rOff < data.Length && rSize > 0)
                {
                    uint len = Math.Min(rSize, (uint)(data.Length - rOff));
                    entropy = CalcEntropy(data, rOff, len);
                }

                list.Add(new RawSection
                {
                    Name            = name,
                    VirtualAddress  = vAddr,
                    VirtualSize     = vSize,
                    RawOffset       = rOff,
                    RawSize         = rSize,
                    Characteristics = chars,
                    Entropy         = entropy,
                });
            }
            return list;
        }

        // парсим таблицу импортов — достаём названия dll и функций
        private static void ReadImports(byte[] data, uint tableOff, List<RawSection> secs, bool is64, List<ImportEntry> imports)
        {
            uint off = tableOff;
            // IMAGE_IMPORT_DESCRIPTOR это 20 байт, нулевая запись означает конец
            while (off + 20 <= data.Length)
            {
                uint origThunk  = BitConverter.ToUInt32(data, (int)off);
                uint nameRva    = BitConverter.ToUInt32(data, (int)off + 12);
                uint firstThunk = BitConverter.ToUInt32(data, (int)off + 16);

                if (nameRva == 0 && firstThunk == 0) break;

                uint nameOff = Rva2Off(nameRva, secs);
                string dll   = nameOff > 0 ? ReadZ(data, nameOff) : "?";

                uint thunkRva = origThunk != 0 ? origThunk : firstThunk;
                uint thunkOff = Rva2Off(thunkRva, secs);

                if (thunkOff != 0)
                {
                    int step = is64 ? 8 : 4; // для 64 бит thunk запись занимает 8 байт
                    uint ptr = thunkOff;

                    while (ptr + step <= data.Length)
                    {
                        if (is64)
                        {
                            ulong val = BitConverter.ToUInt64(data, (int)ptr);
                            if (val == 0) break;

                            if ((val & 0x8000000000000000UL) != 0) // старший бит = импорт по ординалу
                                imports.Add(new ImportEntry { Dll = dll, Function = $"Ordinal#{val & 0x7FFFFFFFFFFFFFFF}" });
                            else
                            {
                                uint fo = Rva2Off((uint)(val & 0xFFFFFFFF), secs);
                                if (fo + 2 < data.Length)
                                    imports.Add(new ImportEntry { Dll = dll, Function = ReadZ(data, fo + 2) });
                            }
                        }
                        else
                        {
                            uint val = BitConverter.ToUInt32(data, (int)ptr);
                            if (val == 0) break;

                            if ((val & 0x80000000) != 0) // старший бит = ординал
                                imports.Add(new ImportEntry { Dll = dll, Function = $"Ordinal#{val & 0x7FFFFFFF}" });
                            else
                            {
                                uint fo = Rva2Off(val, secs);
                                if (fo + 2 < data.Length)
                                    imports.Add(new ImportEntry { Dll = dll, Function = ReadZ(data, fo + 2) });
                            }
                        }
                        ptr += (uint)step;
                    }
                }

                off += 20;
            }
        }

        // переводим rva в реальное смещение в файле через таблицу секций
        // ваще не уверен что правильно работает если rva попадает в заголовок а не в секцию, но пока не встречал такого
        private static uint Rva2Off(uint rva, List<RawSection> secs)
        {
            foreach (var s in secs)
            {
                uint span = Math.Max(s.VirtualSize, s.RawSize);
                if (rva >= s.VirtualAddress && rva < s.VirtualAddress + span)
                    return s.RawOffset + (rva - s.VirtualAddress);
            }
            return 0;
        }

        // энтропия шеннона — чем выше тем больше похоже на зашифрованные или сжатые данные
        public static double CalcEntropy(byte[] data, uint offset, uint length)
        {
            int[] freq = new int[256];
            for (uint i = offset; i < offset + length; i++)
                freq[data[i]]++;

            double e = 0, n = length;
            for (int i = 0; i < 256; i++)
            {
                if (freq[i] > 0)
                {
                    double p = freq[i] / n;
                    e -= p * Math.Log(p, 2);
                }
            }
            return e;
        }

        // перегрузка для удобства когда надо посчитать энтропию всего массива
        public static double CalcEntropy(byte[] data)
            => data.Length == 0 ? 0 : CalcEntropy(data, 0, (uint)data.Length);

        // читаем строку до нулевого байта, максимум max символов
        private static string ReadZ(byte[] data, uint off, int max = 256)
        {
            var sb = new StringBuilder();
            while (off < data.Length && data[off] != 0 && sb.Length < max)
                sb.Append((char)data[off++]);
            return sb.ToString();
        }
    }
}
