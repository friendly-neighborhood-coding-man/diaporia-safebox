// SafeBox V6 local fingerprint gate helper (Windows Biometric Framework + CNG key).
//
// Build (no Visual Studio needed, .NET Framework 4 csc):
//   %WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe /nologo /optimize /target:exe /out:winbio-gate.exe /r:System.Core.dll /r:System.Windows.Forms.dll /r:System.Drawing.dll WinBioGate.cs
//
// Commands (all output is ONE line of JSON on stdout; nothing else is printed):
//   probe                                   enumerate fingerprint units / open a system-pool session (no capture)
//   key   --name <keyName>                  create-or-open the gate key (TPM: Microsoft Platform Crypto Provider; else
//                                           software KSP, reported as WINBIO_SOFTWARE_KEY) and return its public key
//   identify [--timeout <s>] [--prompt <text>]
//                                           sensor check only: WinBioIdentify + current-user check, NO signature
//   verify-sign --name <keyName> --hash <64 hex> [--timeout <s>] [--prompt <text>]
//                                           ask the physical sensor for a fingerprint (WinBioIdentify, system pool);
//                                           ONLY if the identified Windows account is the current user, sign the
//                                           given SHA-256 hash with the gate key (ECDSA P-256, IEEE-P1363 r||s).
//
// What this proves and what it does not: a signature means "this helper, running as the current user on this laptop,
// observed a WinBio MATCH for the current Windows account and then signed this hash". It never handles a PIN, never
// exports biometric data (samples, templates, scores), and never signs without a MATCH. It is NOT hardware attestation:
// a compromised OS or a modified helper could sign without a finger. There is deliberately no command that signs
// without a fingerprint (the enrollment proof-of-possession also goes through verify-sign).
//
// Window focus: in the system pool, the Windows Biometric Service delivers a capture only to the process whose window
// has the foreground. While waiting, the helper shows a small top-most window ("SafeBox fingerprint gate").
// Freshness: no capture starts until the owner clicks "Start fingerprint check" in that window, and a result that
// arrives too fast (finger already resting, or a queued capture) is discarded; see IdentifyFocused.
using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using System.Drawing;

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

  [STAThread]
  static int Main(string[] args) {
    try {
      string cmd = args.Length > 0 ? args[0] : "";
      if (cmd == "probe") return Probe();
      if (cmd == "key") return Key(Arg(args, "--name"));
      if (cmd == "identify") return VerifySign(null, null, int.Parse(Arg(args, "--timeout") ?? "60"), Arg(args, "--prompt"), false);
      if (cmd == "verify-sign") return VerifySign(Arg(args, "--name"), Arg(args, "--hash"), int.Parse(Arg(args, "--timeout") ?? "60"), Arg(args, "--prompt"), true);
      return Fail("USAGE", 0, "probe | key --name N | identify [--timeout S] [--prompt T] | verify-sign --name N --hash HEX [--timeout S] [--prompt T]");
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

  [DllImport("user32.dll")] static extern bool SetForegroundWindow(IntPtr hWnd);

  // Freshness (run 7 finding: the PAYMENT gate MATCHed ~6 s after its window opened, ~9 s after the previous Windows
  // Hello touch, while the owner reports no touch). A capture is accepted ONLY if:
  //   1. the owner first clicked "Start fingerprint check" in this window (a deliberate act for THIS prompt), AND
  //   2. capture began in a NEW window at least ArmDelayMs after that click (the window says TOUCH NOW only then), AND
  //   3. the sensor first stayed SILENT for QuietMs after that pause (anything delivered then is discarded), AND
  //   4. WinBioIdentify took at least MinCaptureMs (a finger already resting on the sensor, or a capture queued by
  //      the service, returns almost at once; such a result is DISCARDED and a NEW touch is required).
  // Discarded results are counted in the output. Diagnostics carry no biometric data (time, sub-factor index only).
  const int ArmDelayMs = 1000, MinCaptureMs = 700, MaxDiscards = 25, QuietMs = 3000, QuietMaxS = 30;
  static long LastMs = -1; static byte LastSub = 0; static uint LastReject = 0; static int Discarded = 0; static long ArmedAfterMs = -1; static int Calls = 0; static int InactiveTicks = 0; static int QuietDiscards = 0;

  /** Phase 1: a window with a Start button (mouse only). Returns true if the owner clicked it before the deadline. */
  static bool ArmByClick(string prompt, DateTime deadline) {
    bool clicked = false; var shown = new System.Diagnostics.Stopwatch();
    var form = new Form { Text = "SafeBox fingerprint gate", TopMost = true, Width = 560, Height = 280, StartPosition = FormStartPosition.CenterScreen, FormBorderStyle = FormBorderStyle.FixedDialog, MaximizeBox = false, MinimizeBox = false };
    var label = new Label { Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleCenter, Font = new Font("Segoe UI", 12f),
      Text = (prompt ?? "") + "\n\nKeep your finger OFF the sensor.\nClick \"Start fingerprint check\" to approve with your fingerprint." };
    var btn = new Button { Text = "Start fingerprint check", TabStop = false, Dock = DockStyle.Bottom, Height = 48, Font = new Font("Segoe UI", 12f, FontStyle.Bold) };
    form.Controls.Add(label); form.Controls.Add(btn);
    // mouse only: MouseClick never fires for Space/Enter, so a keystroke typed into the focused gate window cannot arm it
    btn.MouseClick += (o, e) => { if (clicked) return; clicked = true; ArmedAfterMs = shown.ElapsedMilliseconds; form.Close(); };
    var timer = new System.Windows.Forms.Timer { Interval = 150 };
    timer.Tick += (o, e) => { if (DateTime.UtcNow > deadline) { timer.Stop(); form.Close(); } };
    form.Shown += (o, e) => { shown.Start(); form.Activate(); SetForegroundWindow(form.Handle); form.ActiveControl = label; timer.Start(); };
    Application.Run(form);
    return clicked;
  }

  /** Phase 2 (the capture path proven in run 6): a NEW top-most window takes the foreground and WinBioIdentify starts
   *  when it is shown. Results faster than MinCaptureMs are discarded and a new touch is required. */
  static void IdentifyFocused(IntPtr s, IntPtr ident, DateTime deadline, string prompt, out int idHr, out uint unit, out bool done) {
    int hr = unchecked((int)0x80004004); uint u = 0; bool fin = false; bool stop = false;
    var form = new Form { Text = "SafeBox fingerprint gate", TopMost = true, Width = 560, Height = 230, StartPosition = FormStartPosition.CenterScreen, FormBorderStyle = FormBorderStyle.FixedDialog, MaximizeBox = false, MinimizeBox = false };
    var label = new Label { Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleCenter, Font = new Font("Segoe UI", 12f),
      Text = (prompt ?? "") + "\n\nTOUCH the fingerprint sensor NOW.\n\nIf nothing happens when you touch it, click this window once, then touch again." };
    form.Controls.Add(label);
    Action<string> say = (txt) => { try { form.BeginInvoke((Action)(() => { label.Text = (prompt ?? "") + "\n\n" + txt; })); } catch { } };
    var t = new Thread(() => {
      // QUIET PHASE (run 7 + run 8 finding: a MATCH arrived ~2 s into capture with no touch, each time a few seconds
      // after a Windows Hello fingerprint use, i.e. the sensor/driver/service delivered an earlier capture). Before any
      // capture can count, the sensor must stay silent for QuietMs: every result that arrives during a quiet window
      // (match or not) is discarded and the quiet window restarts. Only after a full silent window does "TOUCH NOW"
      // appear and the counted capture begin.
      say("Checking the sensor is quiet: keep your finger OFF...");
      var quietStart = DateTime.UtcNow;
      while (!stop) {
        if ((DateTime.UtcNow - quietStart).TotalSeconds > QuietMaxS) { hr = unchecked((int)0x8009FFFE); fin = true; return; }
        bool quietCancel = false;
        using (var qt = new System.Threading.Timer((_) => { quietCancel = true; WinBioCancel(s); }, null, QuietMs, Timeout.Infinite)) {
          uint qs2 = 0; byte qs = 0; Calls++;
          WinBioIdentify(s, out u, ident, out qs, out qs2);
        }
        if (stop) return;
        if (quietCancel) break;                    // a full window with nothing from the sensor
        QuietDiscards++; Thread.Sleep(300);        // something arrived without a prompt: discard, start a new window
        say("Something reached the sensor. LIFT your finger and keep it OFF...");
      }
      for (int i = 0; i < 128; i++) Marshal.WriteByte(ident, i, 0);
      while (!stop) {
        say("TOUCH the fingerprint sensor NOW.");
        uint sub2 = 0; byte sub = 0; Calls++; var sw = System.Diagnostics.Stopwatch.StartNew();
        int r = WinBioIdentify(s, out u, ident, out sub, out sub2); sw.Stop();
        LastMs = sw.ElapsedMilliseconds; LastSub = sub; LastReject = sub2;
        if (stop) break;
        if (sw.ElapsedMilliseconds < MinCaptureMs) { // resting finger or queued capture: never accept it
          if (++Discarded >= MaxDiscards) { hr = unchecked((int)0x8009FFFE); fin = true; break; }
          say("Too fast (finger already on the sensor?). LIFT your finger, then TOUCH again.");
          Thread.Sleep(800); continue;
        }
        hr = r; fin = true; break;
      }
    });
    t.IsBackground = true;
    var timer = new System.Windows.Forms.Timer { Interval = 150 };
    timer.Tick += (o, e) => { if (fin || DateTime.UtcNow > deadline) { timer.Stop(); form.Close(); } else if (Form.ActiveForm != form) { label.ForeColor = Color.DarkRed; InactiveTicks++; } else { label.ForeColor = Color.Black; } };
    form.Shown += (o, e) => { form.Activate(); SetForegroundWindow(form.Handle); t.Start(); timer.Start(); };
    Application.Run(form);
    if (!fin) { stop = true; WinBioCancel(s); t.Join(3000); }
    idHr = hr; unit = u; done = fin;
  }

  static int VerifySign(string name, string hashHex, int timeoutS, string prompt, bool sign) {
    var hash = new byte[32];
    if (sign) {
      if (hashHex == null || hashHex.Length != 64) return Fail("BAD_HASH");
      for (int i = 0; i < 32; i++) hash[i] = Convert.ToByte(hashHex.Substring(i * 2, 2), 16);
    }
    if (timeoutS < 5 || timeoutS > 300) return Fail("BAD_TIMEOUT");
    IntPtr s; int hr = WinBioOpenSession(WINBIO_TYPE_FINGERPRINT, WINBIO_POOL_SYSTEM, WINBIO_FLAG_DEFAULT, IntPtr.Zero, UIntPtr.Zero, new IntPtr(1), out s);
    if (hr != 0) return Fail("FINGERPRINT_ONLY_UNSUPPORTED", hr, "WinBioOpenSession");
    IntPtr ident = Marshal.AllocHGlobal(128);
    try {
      for (int i = 0; i < 128; i++) Marshal.WriteByte(ident, i, 0);
      uint unit; int idHr; bool done;
      Console.Error.Write("Touch the fingerprint sensor now (" + timeoutS + " s)...\n");
      var deadline = DateTime.UtcNow.AddSeconds(timeoutS);
      if (!ArmByClick(prompt, deadline)) return Fail("BIOMETRIC_TIMEOUT", 0, "not started (no click)");
      Thread.Sleep(ArmDelayMs); // a finger used just before has time to lift; no capture is pending during this pause
      IdentifyFocused(s, ident, deadline, prompt, out idHr, out unit, out done);
      if (!done) return Fail("BIOMETRIC_TIMEOUT", 0, "no fresh touch; discarded " + Discarded + ", quiet-phase discards " + QuietDiscards + ", identify calls " + Calls + ", window inactive " + (InactiveTicks * 150) + " ms while capturing");
      Console.Error.Write("WinBioIdentify returned after " + LastMs + " ms (hr 0x" + idHr.ToString("X8") + ", subFactor " + LastSub + ", reject " + LastReject + ", discarded " + Discarded + ", armed after " + ArmedAfterMs + " ms)\n");
      if (unchecked((uint)idHr) == 0x8009FFFE) return Fail("BIOMETRIC_STALE", 0, "sensor never quiet / finger never lifted: " + Discarded + " instant + " + QuietDiscards + " quiet-phase captures discarded");
      if (idHr != 0) {
        uint u = unchecked((uint)idHr);
        // winerror.h: 0x80098003 WINBIO_E_UNKNOWN_ID, 0x80098004 WINBIO_E_CANCELED, 0x80098005 WINBIO_E_NO_MATCH,
        // 0x80098006 WINBIO_E_CAPTURE_ABORTED, 0x80098008 WINBIO_E_BAD_CAPTURE
        if (u == 0x80098003 || u == 0x80098005) return Fail("BIOMETRIC_NO_MATCH", idHr);
        if (u == 0x80098008) return Fail("BIOMETRIC_NO_MATCH", idHr, "bad capture");
        if (u == 0x80098004 || u == 0x80098006) return Fail("BIOMETRIC_CANCELLED", idHr);
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
      string diag = ",\"elapsedMs\":" + LastMs + ",\"subFactor\":" + LastSub + ",\"discarded\":" + Discarded + ",\"quietDiscards\":" + QuietDiscards + ",\"armedAfterMs\":" + ArmedAfterMs;
      if (!sign) return Out("{\"ok\":true,\"result\":\"MATCH\",\"unit\":" + unit + diag + "}");
      string kind; var k = OpenOrCreate(name, out kind);
      byte[] sig; using (var e = new ECDsaCng(k)) sig = e.SignHash(hash); // IEEE-P1363 r||s
      return Out("{\"ok\":true,\"result\":\"MATCH\",\"unit\":" + unit + ",\"kind\":" + Q(kind) + ",\"sig\":" + Q(Hex(sig)) + diag + "}");
    } finally { Marshal.FreeHGlobal(ident); WinBioCloseSession(s); }
  }
}
