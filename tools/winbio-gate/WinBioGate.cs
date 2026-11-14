// SafeBox V6 local fingerprint gate helper (Windows Biometric Framework + CNG key).
//
// Build (no Visual Studio needed, .NET Framework 4 csc):
//   %WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe /nologo /optimize /target:exe /out:winbio-gate.exe /r:System.Core.dll WinBioGate.cs
//
// Commands (all output is ONE line of JSON on stdout; nothing else is printed):
//   probe                                   enumerate fingerprint units / open a system-pool session (no capture)
//   key   --name <keyName>                  create-or-open the gate key (TPM: Microsoft Platform Crypto Provider; else
//                                           software KSP, reported as WINBIO_SOFTWARE_KEY) and return its public key
//   verify-sign --name <keyName> --hash <64 hex> [--timeout <s>]
//                                           ask the physical sensor for a fingerprint (WinBioIdentify, system pool);
//                                           ONLY if the identified Windows account is the current user, sign the
//                                           given SHA-256 hash with the gate key (ECDSA P-256, IEEE-P1363 r||s).
//
// What this proves and what it does not: a signature means "this helper, running as the current user on this laptop,
// observed a WinBio MATCH for the current Windows account and then signed this hash". It never handles a PIN, never
// exports biometric data (samples, templates, scores), and never signs without a MATCH. It is NOT hardware attestation:
// a compromised OS or a modified helper could sign without a finger. There is deliberately no command that signs
// without a fingerprint (the enrollment proof-of-possession also goes through verify-sign).
using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading;

static class WinBioGate {
  const uint WINBIO_TYPE_FINGERPRINT = 0x00000008;
  const uint WINBIO_POOL_SYSTEM = 1;
  const uint WINBIO_FLAG_DEFAULT = 0;
  const uint WINBIO_ID_TYPE_SID = 3;

  [DllImport("winbio.dll")] static extern int WinBioOpenSession(uint factor, uint poolType, uint flags, IntPtr unitArray, UIntPtr unitCount, IntPtr databaseId, out IntPtr session);
  [DllImport("winbio.dll")] static extern int WinBioCloseSession(IntPtr session);
  [DllImport("winbio.dll")] static extern int WinBioIdentify(IntPtr session, out uint unitId, IntPtr identity, out byte subFactor, out uint rejectDetail);
  [DllImport("winbio.dll")] static extern int WinBioCancel(IntPtr session);
  [DllImport("winbio.dll")] static extern int WinBioEnumBiometricUnits(uint factor, out IntPtr unitSchemaArray, out UIntPtr unitCount);
  [DllImport("winbio.dll")] static extern int WinBioFree(IntPtr address);

  static string Arg(string[] a, string k) { for (int i = 0; i + 1 < a.Length; i++) if (a[i] == k) return a[i + 1]; return null; }
  static string Hex(byte[] b) { var s = new StringBuilder(b.Length * 2); foreach (var x in b) s.Append(x.ToString("x2")); return s.ToString(); }
  static string Q(string s) { return "\"" + s.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\""; }
  static int Out(string json) { Console.Out.Write(json + "\n"); return 0; }
  static int Fail(string code, int hr = 0, string detail = null) {
    Console.Out.Write("{\"ok\":false,\"code\":" + Q(code) + (hr != 0 ? ",\"hr\":\"0x" + hr.ToString("X8") + "\"" : "") + (detail != null ? ",\"detail\":" + Q(detail) : "") + "}\n");
    return 1;
  }

  static int Main(string[] args) {
    try {
      string cmd = args.Length > 0 ? args[0] : "";
      if (cmd == "probe") return Probe();
      if (cmd == "key") return Key(Arg(args, "--name"));
      if (cmd == "verify-sign") return VerifySign(Arg(args, "--name"), Arg(args, "--hash"), int.Parse(Arg(args, "--timeout") ?? "30"));
      return Fail("USAGE", 0, "probe | key --name N | verify-sign --name N --hash HEX [--timeout S]");
    } catch (Exception e) { return Fail("HELPER_EXCEPTION", 0, e.GetType().Name); }
  }

  static int Probe() {
    IntPtr arr; UIntPtr n;
    int hr = WinBioEnumBiometricUnits(WINBIO_TYPE_FINGERPRINT, out arr, out n);
    if (hr != 0) return Fail("WINBIO_ENUM_FAILED", hr);
    WinBioFree(arr);
    IntPtr s; int hr2 = WinBioOpenSession(WINBIO_TYPE_FINGERPRINT, WINBIO_POOL_SYSTEM, WINBIO_FLAG_DEFAULT, IntPtr.Zero, UIntPtr.Zero, new IntPtr(1), out s);
    if (hr2 == 0) WinBioCloseSession(s);
    return Out("{\"ok\":true,\"units\":" + n.ToUInt64() + ",\"systemPoolSession\":" + (hr2 == 0 ? "\"OPENED\"" : "\"0x" + hr2.ToString("X8") + "\"") + "}");
  }

  static CngKey OpenOrCreate(string name, out string kind) {
    if (string.IsNullOrEmpty(name) || name.Length > 64) throw new ArgumentException("name");
    foreach (var p in new[] { "Microsoft Platform Crypto Provider", "Microsoft Software Key Storage Provider" }) {
      var prov = new CngProvider(p);
      kind = p.StartsWith("Microsoft Platform") ? "WINBIO_TPM" : "WINBIO_SOFTWARE_KEY";
      try { if (CngKey.Exists(name, prov)) return CngKey.Open(name, prov); } catch { }
      try {
        var cp = new CngKeyCreationParameters { Provider = prov, ExportPolicy = CngExportPolicies.None, KeyCreationOptions = CngKeyCreationOptions.None };
        return CngKey.Create(CngAlgorithm.ECDsaP256, name, cp);
      } catch { /* try the next provider */ }
    }
    throw new CryptographicException("no key storage provider");
  }

  static int Key(string name) {
    string kind; var k = OpenOrCreate(name, out kind);
    byte[] blob = k.Export(CngKeyBlobFormat.EccPublicBlob); // BCRYPT_ECCKEY_BLOB: magic(4) cbKey(4) X Y
    int cb = BitConverter.ToInt32(blob, 4);
    var x = new byte[cb]; var y = new byte[cb]; Buffer.BlockCopy(blob, 8, x, 0, cb); Buffer.BlockCopy(blob, 8 + cb, y, 0, cb);
    return Out("{\"ok\":true,\"kind\":" + Q(kind) + ",\"x\":" + Q(Hex(x)) + ",\"y\":" + Q(Hex(y)) + ",\"provider\":" + Q(k.Provider.Provider) + "}");
  }

  static int VerifySign(string name, string hashHex, int timeoutS) {
    if (hashHex == null || hashHex.Length != 64) return Fail("BAD_HASH");
    var hash = new byte[32]; for (int i = 0; i < 32; i++) hash[i] = Convert.ToByte(hashHex.Substring(i * 2, 2), 16);
    IntPtr s; int hr = WinBioOpenSession(WINBIO_TYPE_FINGERPRINT, WINBIO_POOL_SYSTEM, WINBIO_FLAG_DEFAULT, IntPtr.Zero, UIntPtr.Zero, new IntPtr(1), out s);
    if (hr != 0) return Fail("FINGERPRINT_ONLY_UNSUPPORTED", hr, "WinBioOpenSession");
    IntPtr ident = Marshal.AllocHGlobal(128);
    try {
      for (int i = 0; i < 128; i++) Marshal.WriteByte(ident, i, 0);
      uint unit = 0, reject = 0; byte sub = 0; int idHr = unchecked((int)0x80004004); bool done = false;
      Console.Error.Write("Touch the fingerprint sensor now (" + timeoutS + " s)...\n");
      var t = new Thread(() => { idHr = WinBioIdentify(s, out unit, ident, out sub, out reject); done = true; });
      t.IsBackground = true; t.Start();
      if (!t.Join(timeoutS * 1000)) { WinBioCancel(s); t.Join(3000); return Fail("BIOMETRIC_TIMEOUT"); }
      if (!done) return Fail("BIOMETRIC_TIMEOUT");
      if (idHr != 0) {
        uint u = unchecked((uint)idHr);
        if (u == 0x80098005 || u == 0x80098006) return Fail("BIOMETRIC_NO_MATCH", idHr);   // WINBIO_E_UNKNOWN_ID / NO_MATCH
        if (u == 0x80098008) return Fail("BIOMETRIC_NO_MATCH", idHr, "bad capture");      // WINBIO_E_BAD_CAPTURE
        if (u == 0x80098004) return Fail("BIOMETRIC_CANCELLED", idHr);                    // WINBIO_E_CANCELED
        if (u == 0x8009802C || u == 0x8009801B) return Fail("BIOMETRIC_LOCKOUT", idHr);
        return Fail("FINGERPRINT_ONLY_UNSUPPORTED", idHr, "WinBioIdentify");
      }
      // the identified account must be the CURRENT Windows user
      uint type = (uint)Marshal.ReadInt32(ident, 0);
      if (type != WINBIO_ID_TYPE_SID) return Fail("BIOMETRIC_NO_MATCH", 0, "identity type " + type);
      int sidSize = Marshal.ReadInt32(ident, 4);
      if (sidSize <= 0 || sidSize > 68) return Fail("BIOMETRIC_NO_MATCH", 0, "sid size");
      var sid = new byte[sidSize]; Marshal.Copy(IntPtr.Add(ident, 8), sid, 0, sidSize);
      var me = WindowsIdentity.GetCurrent().User; var mine = new byte[me.BinaryLength]; me.GetBinaryForm(mine, 0);
      if (Hex(sid) != Hex(mine)) return Fail("BIOMETRIC_NO_MATCH", 0, "different Windows account");
      string kind; var k = OpenOrCreate(name, out kind);
      byte[] sig; using (var e = new ECDsaCng(k)) sig = e.SignHash(hash); // IEEE-P1363 r||s
      return Out("{\"ok\":true,\"result\":\"MATCH\",\"unit\":" + unit + ",\"kind\":" + Q(kind) + ",\"sig\":" + Q(Hex(sig)) + "}");
    } finally { Marshal.FreeHGlobal(ident); WinBioCloseSession(s); }
  }
}
