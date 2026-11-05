using System.Buffers.Binary;
using System.Net;
using System.Text;

namespace ZapretHub;

internal static class DnsWire
{
    internal static ushort U16(ReadOnlySpan<byte> b, int p) => BinaryPrimitives.ReadUInt16BigEndian(b[p..]);
    internal static void Put(byte[] b, int p, ushort n) => BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(p), n);

    internal static bool Question(byte[] b, out string name, out int end)
    {
        name = ""; end = 0;
        if (b.Length < 17 || (b[2] & 0xf8) != 0 || U16(b, 4) != 1 || U16(b, 6) != 0 || U16(b, 8) != 0) return false;
        int p = 12; var parts = new List<string>();
        while (p < b.Length)
        {
            int n = b[p++];
            if (n == 0)
            {
                if (p + 4 > b.Length || p - 12 > 255 || U16(b, p + 2) != 1) return false;
                name = string.Join('.', parts).ToLowerInvariant(); end = p + 4; return name.Length > 0;
            }
            if (n > 63 || p + n > b.Length) return false;
            for (int i = 0; i < n; i++)
                if (b[p + i] < 33 || b[p + i] > 126 || b[p + i] == '.') return false;
            parts.Add(Encoding.ASCII.GetString(b, p, n)); p += n;
        }
        return false;
    }

    internal static byte[] Query(string name, ushort type = 1)
    {
        using var ms = new MemoryStream();
        var header = new byte[12]; Put(header, 0, (ushort)Random.Shared.Next(65536)); header[2] = 1; Put(header, 4, 1); ms.Write(header);
        foreach (var part in name.TrimEnd('.').Split('.')) { ms.WriteByte((byte)part.Length); ms.Write(Encoding.ASCII.GetBytes(part)); }
        ms.WriteByte(0); ms.WriteByte((byte)(type >> 8)); ms.WriteByte((byte)type); ms.WriteByte(0); ms.WriteByte(1);
        return ms.ToArray();
    }

    internal static byte[] Error(byte[] query, int code)
    {
        bool valid = Question(query, out _, out int end);
        var r = new byte[valid ? end : 12];
        if (query.Length >= 2) Array.Copy(query, r, 2);
        r[2] = (byte)(0x80 | (query.Length > 2 ? query[2] & 1 : 0)); r[3] = (byte)(0x80 | code);
        if (valid) { Put(r, 4, 1); Array.Copy(query, 12, r, 12, end - 12); }
        return r;
    }

    internal static bool Reply(byte[] query, byte[] response)
    {
        if (!Question(query, out _, out int end) || response.Length < end || response.Length > 65535 ||
            U16(query, 0) != U16(response, 0) || (response[2] & 0x80) == 0 ||
            (response[2] & 0x78) != 0 || U16(response, 4) != 1 ||
            !query.AsSpan(end - 4, 4).SequenceEqual(response.AsSpan(end - 4, 4))) return false;
        for (int i = 12; i < end - 4; i++)
        {
            byte a = query[i], b = response[i];
            if (a is >= 65 and <= 90) a += 32;
            if (b is >= 65 and <= 90) b += 32;
            if (a != b) return false;
        }
        // Validate all record boundaries, including compressed names. No untrusted pointer is followed.
        int p = end;
        int records = U16(response, 6) + U16(response, 8) + U16(response, 10);
        for (int i = 0; i < records; i++)
        {
            if (!SkipName(response, ref p) || p + 10 > response.Length) return false;
            int size = U16(response, p + 8); p += 10;
            if (p + size > response.Length) return false;
            p += size;
        }
        return p == response.Length;
    }

    private static bool SkipName(byte[] b, ref int p)
    {
        int start = p;
        while (p < b.Length && p - start <= 255)
        {
            int n = b[p++];
            if (n == 0) return true;
            if ((n & 0xc0) == 0xc0)
            {
                if (p >= b.Length || ((n & 63) * 256 + b[p]) >= b.Length) return false;
                p++; return true;
            }
            if (n > 63 || p + n > b.Length) return false;
            p += n;
        }
        return false;
    }

    internal static List<IPAddress> Addresses(byte[] query, byte[] response)
    {
        var result = new List<IPAddress>();
        if (!Reply(query, response) || (response[3] & 15) != 0) return result;
        Question(query, out _, out int p);
        for (int i = 0; i < U16(response, 6); i++)
        {
            if (!SkipName(response, ref p)) break;
            int type = U16(response, p), size = U16(response, p + 8); p += 10;
            if ((type == 1 && size == 4) || (type == 28 && size == 16)) result.Add(new IPAddress(response.AsSpan(p, size)));
            p += size;
        }
        return result;
    }
}
