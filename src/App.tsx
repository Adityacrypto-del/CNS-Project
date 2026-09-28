import React, { useState, useEffect } from "react"
import LycorisSpecimen from "@/components/ui/lycoris-specimen"
import { WEB_APP_URL, WEB_APP_PORT, API_URL, API_PORT } from "@/lib/links"
import { ShieldCheck, Lock, Key, Cpu, Sparkles, Terminal, ArrowUpRight, CheckCircle2, UserCheck, Play, RefreshCw } from "lucide-react"

export default function App() {
  const [florets, setFlorets] = useState<number>(6)
  const [seed, setSeed] = useState<number>(7)
  const [crimsonColor, setCrimsonColor] = useState<string>("#e3131b")
  const [alive, setAlive] = useState<boolean>(true)
  const [apiOnline, setApiOnline] = useState<boolean | null>(null)

  useEffect(() => {
    // Check the API health endpoint through the Vite proxy (see vite.config.ts); the API
    // itself only allows CORS from the exam web app, not from this page.
    fetch("/api/v1/health")
      .then((res) => (res.ok ? setApiOnline(true) : setApiOnline(false)))
      .catch(() => setApiOnline(false))
  }, [])

  return (
    <div className="min-h-screen bg-[#050505] text-[#b6b095] selection:bg-[#e3131b] selection:text-white font-sans relative">
      {/* Header Bar */}
      <header className="fixed top-0 left-0 right-0 z-50 bg-[#050505]/80 backdrop-blur-md border-b border-[#b6b095]/10 px-6 py-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-full bg-[#e3131b]/15 border border-[#e3131b]/40 flex items-center justify-center text-[#e3131b]">
            <ShieldCheck className="w-4 h-4" />
          </div>
          <div>
            <h1 className="font-mono text-sm tracking-wider uppercase text-white font-bold">
              Secure Exam <span className="text-[#e3131b]">v2026</span>
            </h1>
            <p className="text-[10px] text-[#b6b095]/60 tracking-widest uppercase">
              End-to-End Encrypted Examination Protocol
            </p>
          </div>
        </div>

        <nav className="hidden md:flex items-center gap-6 text-xs uppercase tracking-widest font-mono">
          <a href="#specimen" className="hover:text-[#e3131b] transition-colors">
            Specimen
          </a>
          <a href="#features" className="hover:text-[#e3131b] transition-colors">
            Security Architecture
          </a>
          <a href="#portals" className="hover:text-[#e3131b] transition-colors">
            Portals & Accounts
          </a>
          <a href="#api" className="hover:text-[#e3131b] transition-colors">
            API Docs
          </a>
        </nav>

        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-white/5 border border-white/10 text-[11px] font-mono">
            <span
              className={`w-2 h-2 rounded-full ${
                apiOnline === true
                  ? "bg-emerald-500 animate-pulse"
                  : apiOnline === false
                  ? "bg-amber-500"
                  : "bg-gray-500 animate-ping"
              }`}
            />
            <span className="text-gray-300">
              {apiOnline === true ? "API Online (8444)" : "API Self-Signed (8444)"}
            </span>
          </div>
          <a
            href={WEB_APP_URL}
            target="_blank"
            rel="noreferrer"
            className="px-4 py-1.5 rounded-full bg-[#e3131b] text-white text-xs font-semibold uppercase tracking-wider hover:bg-[#c10d14] transition-all flex items-center gap-1.5 shadow-lg shadow-[#e3131b]/20"
          >
            <span>Launch Web App</span>
            <ArrowUpRight className="w-3.5 h-3.5" />
          </a>
        </div>
      </header>

      {/* Main Hero & WebGL Specimen Section */}
      <section id="specimen" className="relative">
        <div className="pt-24 pb-8 px-6 max-w-7xl mx-auto flex flex-col md:flex-row md:items-end justify-between border-b border-[#b6b095]/10 gap-6">
          <div>
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-[#e3131b]/10 border border-[#e3131b]/30 text-[#e3131b] text-xs font-mono uppercase tracking-widest mb-4">
              <Sparkles className="w-3.5 h-3.5" />
              <span>Procedural WebGL 3D Specimen</span>
            </div>
            <h2 className="text-4xl md:text-6xl font-light tracking-tight text-white font-serif">
              Lycoris <span className="italic text-[#e3131b]">Radiata</span>
            </h2>
            <p className="mt-2 text-sm text-[#b6b095]/80 max-w-xl">
              Scroll down to scrub through the 6-stage procedural WebGL animation. The red chrome spider lily rotates, blooms, and transforms alongside Art Nouveau typography and end-to-end cryptographic verifications.
            </p>
          </div>

          {/* Interactive Controls Bar */}
          <div className="bg-[#111111]/80 backdrop-blur border border-[#b6b095]/15 p-4 rounded-xl flex flex-wrap gap-4 text-xs font-mono">
            <div className="flex flex-col gap-1">
              <label className="text-[10px] uppercase text-[#b6b095]/60">Florets ({florets})</label>
              <input
                type="range"
                min="3"
                max="8"
                value={florets}
                onChange={(e) => setFlorets(Number(e.target.value))}
                className="accent-[#e3131b] cursor-pointer"
              />
            </div>
            <div className="flex flex-col gap-1">
              <label className="text-[10px] uppercase text-[#b6b095]/60">Morph Seed ({seed})</label>
              <button
                onClick={() => setSeed((s) => (s + 1) % 20)}
                className="px-2.5 py-1 rounded bg-white/5 hover:bg-white/10 text-white flex items-center gap-1 border border-white/10"
              >
                <RefreshCw className="w-3 h-3" />
                <span>Reroll</span>
              </button>
            </div>
            <div className="flex flex-col gap-1">
              <label className="text-[10px] uppercase text-[#b6b095]/60">Accent Color</label>
              <div className="flex items-center gap-2">
                {["#e3131b", "#ff3b00", "#d4af37", "#00e5ff"].map((c) => (
                  <button
                    key={c}
                    onClick={() => setCrimsonColor(c)}
                    className={`w-5 h-5 rounded-full border ${crimsonColor === c ? "scale-110 border-white" : "border-transparent"}`}
                    style={{ backgroundColor: c }}
                  />
                ))}
              </div>
            </div>
            <div className="flex flex-col gap-1">
              <label className="text-[10px] uppercase text-[#b6b095]/60">Motion</label>
              <button
                onClick={() => setAlive(!alive)}
                className={`px-3 py-1 rounded text-xs font-mono border ${
                  alive ? "bg-[#e3131b]/20 border-[#e3131b] text-white" : "bg-white/5 border-white/10 text-gray-400"
                }`}
              >
                {alive ? "Alive" : "Reduced"}
              </button>
            </div>
          </div>
        </div>

        {/* The Lycoris Specimen Component */}
        <LycorisSpecimen
          name="Lycoris"
          studio="CNS Cryptography"
          year="2026"
          florets={florets}
          seed={seed}
          crimson={crimsonColor}
          alive={alive}
          specs={[
            "AES-256-GCM DB at rest",
            "RSA-3072 signatures & exchange",
            "HMAC-SHA256 audit log verification",
            "Strict CSP + WebCrypto IDB storage",
            "TLS 1.3 Transport Channel",
          ]}
          tagline={[
            { text: "Secure" },
            { text: "online", small: true },
            { text: "examination" },
            { text: "system", small: true },
          ]}
          ligatureWord="Affluent"
          multilingual="Sê·cû·rê·Ex·äm"
          links={[
            { label: `WEB APP (PORT ${WEB_APP_PORT})`, href: WEB_APP_URL },
            { label: `HTTPS API (PORT ${API_PORT})`, href: `${API_URL}/api/v1/health` },
          ]}
        />
      </section>

      {/* Security Architecture Section */}
      <section id="features" className="py-24 px-6 max-w-7xl mx-auto border-t border-[#b6b095]/10">
        <div className="text-center max-w-3xl mx-auto mb-16">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-[#e3131b]/10 border border-[#e3131b]/30 text-[#e3131b] text-xs font-mono uppercase tracking-widest mb-3">
            <Lock className="w-3.5 h-3.5" />
            <span>Cryptographic Foundations</span>
          </div>
          <h2 className="text-3xl md:text-5xl font-light text-white font-serif">
            Zero-Trust Architecture for Online Exams
          </h2>
          <p className="mt-4 text-sm text-[#b6b095]/70">
            Every administrative action, question paper, student submission, receipt, and result is signed and verified across multiple defense-in-depth layers.
          </p>
        </div>

        <div className="grid md:grid-cols-3 gap-8">
          <div className="p-6 rounded-2xl bg-[#0d0d0d] border border-[#b6b095]/15 hover:border-[#e3131b]/50 transition-all group">
            <div className="w-12 h-12 rounded-xl bg-[#e3131b]/10 border border-[#e3131b]/30 flex items-center justify-center text-[#e3131b] mb-6 group-hover:scale-110 transition-transform">
              <Key className="w-6 h-6" />
            </div>
            <h3 className="text-xl font-medium text-white mb-2">In-Browser Keys</h3>
            <p className="text-xs text-[#b6b095]/70 leading-relaxed">
              RSA-3072 key pairs are generated on client devices using standard WebCrypto APIs. Private keys are saved to IndexedDB encrypted via PBKDF2 (600,000 rounds) + AES-256.
            </p>
          </div>

          <div className="p-6 rounded-2xl bg-[#0d0d0d] border border-[#b6b095]/15 hover:border-[#e3131b]/50 transition-all group">
            <div className="w-12 h-12 rounded-xl bg-[#e3131b]/10 border border-[#e3131b]/30 flex items-center justify-center text-[#e3131b] mb-6 group-hover:scale-110 transition-transform">
              <ShieldCheck className="w-6 h-6" />
            </div>
            <h3 className="text-xl font-medium text-white mb-2">Signed Receipts & Results</h3>
            <p className="text-xs text-[#b6b095]/70 leading-relaxed">
              Submissions yield instant cryptographic proof. Examiner scores and student answers carry RSA-PSS digital signatures preventing tampering or non-repudiation.
            </p>
          </div>

          <div className="p-6 rounded-2xl bg-[#0d0d0d] border border-[#b6b095]/15 hover:border-[#e3131b]/50 transition-all group">
            <div className="w-12 h-12 rounded-xl bg-[#e3131b]/10 border border-[#e3131b]/30 flex items-center justify-center text-[#e3131b] mb-6 group-hover:scale-110 transition-transform">
              <Cpu className="w-6 h-6" />
            </div>
            <h3 className="text-xl font-medium text-white mb-2">Dual Protocol Transports</h3>
            <p className="text-xs text-[#b6b095]/70 leading-relaxed">
              Serves both a high-efficiency TLS socket channel for native CLI clients (port 8443) and an HTTPS JSON API with strict CSP policies for modern browser apps (port 8444 & 5173).
            </p>
          </div>
        </div>
      </section>

      {/* Portals & Demo Accounts Section */}
      <section id="portals" className="py-24 px-6 bg-[#080808] border-t border-[#b6b095]/10">
        <div className="max-w-7xl mx-auto">
          <div className="flex flex-col md:flex-row md:items-end justify-between mb-12 gap-6">
            <div>
              <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-[#e3131b]/10 border border-[#e3131b]/30 text-[#e3131b] text-xs font-mono uppercase tracking-widest mb-3">
                <UserCheck className="w-3.5 h-3.5" />
                <span>Interactive Access</span>
              </div>
              <h2 className="text-3xl md:text-5xl font-light text-white font-serif">
                System Demo Accounts
              </h2>
            </div>
            <p className="text-xs text-[#b6b095]/70 max-w-md">
              Use these pre-initialized credentials to test live student exams, submit answers, or manage exams as an examiner.
            </p>
          </div>

          <div className="grid md:grid-cols-2 gap-8">
            {/* Examiner Card */}
            <div className="p-8 rounded-2xl bg-[#0e0e0e] border border-[#e3131b]/30 relative overflow-hidden">
              <div className="absolute top-0 right-0 px-4 py-1.5 bg-[#e3131b] text-white text-[10px] font-mono uppercase font-bold tracking-widest rounded-bl-xl">
                Examiner Role
              </div>
              <h3 className="text-2xl font-serif text-white mb-1">Dr. Meera Nair</h3>
              <p className="text-xs text-[#e3131b] font-mono mb-6">Username: examiner</p>
              
              <div className="space-y-3 font-mono text-xs mb-8">
                <div className="flex justify-between py-2 border-b border-white/5">
                  <span className="text-gray-400">Password:</span>
                  <span className="text-white font-semibold">Secure#Exam2026</span>
                </div>
                <div className="flex justify-between py-2 border-b border-white/5">
                  <span className="text-gray-400">Key Status:</span>
                  <span className="text-emerald-400">RSA-3072 Pinned</span>
                </div>
                <div className="flex justify-between py-2">
                  <span className="text-gray-400">Capabilities:</span>
                  <span className="text-white">Publish Exams, Grade, Reissue Keys</span>
                </div>
              </div>

              <a
                href={WEB_APP_URL}
                target="_blank"
                rel="noreferrer"
                className="w-full py-3 rounded-xl bg-white/10 hover:bg-white/20 text-white font-mono text-xs uppercase tracking-wider text-center block transition-all border border-white/10"
              >
                Login as Examiner →
              </a>
            </div>

            {/* Student Accounts Card */}
            <div className="p-8 rounded-2xl bg-[#0e0e0e] border border-[#b6b095]/15 relative overflow-hidden">
              <div className="absolute top-0 right-0 px-4 py-1.5 bg-[#b6b095]/20 text-[#b6b095] text-[10px] font-mono uppercase font-bold tracking-widest rounded-bl-xl">
                Student Enrolled
              </div>
              <h3 className="text-2xl font-serif text-white mb-1">Student Candidates</h3>
              <p className="text-xs text-[#b6b095] font-mono mb-6">Demo Candidates: S1001, S1002, S1003</p>

              <div className="space-y-3 font-mono text-xs mb-6">
                <div className="flex justify-between py-2 border-b border-white/5">
                  <span className="text-gray-400">S1001 (Alice):</span>
                  <span className="text-white font-semibold">Alice@Exam2026</span>
                </div>
                <div className="flex justify-between py-2 border-b border-white/5">
                  <span className="text-gray-400">S1002 (Bala):</span>
                  <span className="text-white font-semibold">Bala@Exam2026</span>
                </div>
                <div className="flex justify-between py-2 border-b border-white/5">
                  <span className="text-gray-400">S1003 (Chitra):</span>
                  <span className="text-white font-semibold">Chitra@Exam2026</span>
                </div>
                <div className="flex justify-between py-2">
                  <span className="text-gray-400">S1004 (Pending):</span>
                  <span className="text-amber-400">Code: DEMO-ENRL-CODE-2026</span>
                </div>
              </div>

              <a
                href={WEB_APP_URL}
                target="_blank"
                rel="noreferrer"
                className="w-full py-3 rounded-xl bg-[#e3131b] hover:bg-[#c10d14] text-white font-mono text-xs uppercase tracking-wider text-center block transition-all shadow-lg shadow-[#e3131b]/20"
              >
                Login as Student →
              </a>
            </div>
          </div>
        </div>
      </section>

      {/* Terminal Quickstart Section */}
      <section id="api" className="py-24 px-6 max-w-7xl mx-auto border-t border-[#b6b095]/10">
        <div className="grid md:grid-cols-2 gap-12 items-center">
          <div>
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-[#e3131b]/10 border border-[#e3131b]/30 text-[#e3131b] text-xs font-mono uppercase tracking-widest mb-4">
              <Terminal className="w-3.5 h-3.5" />
              <span>CLI Transport Command Line</span>
            </div>
            <h2 className="text-3xl md:text-4xl font-light text-white font-serif mb-4">
              Command-Line Interface
            </h2>
            <p className="text-sm text-[#b6b095]/70 leading-relaxed mb-6">
              In addition to the Web App, candidates and administrators can interact with the secure server over the encrypted TLS socket or HTTPS API directly from Terminal.
            </p>
            <ul className="space-y-2 text-xs font-mono text-gray-300">
              <li className="flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-[#e3131b]" />
                <span>python -m secure_exam.client (Student CLI)</span>
              </li>
              <li className="flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-[#e3131b]" />
                <span>python -m secure_exam.admin shell (Examiner Admin)</span>
              </li>
            </ul>
          </div>

          <div className="bg-[#0c0c0c] border border-white/10 rounded-2xl p-6 font-mono text-xs text-emerald-400 overflow-x-auto shadow-2xl">
            <div className="flex items-center gap-2 mb-4 text-gray-500 pb-3 border-b border-white/10 text-[11px]">
              <span className="w-3 h-3 rounded-full bg-red-500/80 inline-block" />
              <span className="w-3 h-3 rounded-full bg-yellow-500/80 inline-block" />
              <span className="w-3 h-3 rounded-full bg-green-500/80 inline-block" />
              <span className="ml-2 text-gray-400">bash — secure-exam-cli</span>
            </div>
            <pre className="text-gray-300 leading-relaxed">
<span className="text-[#e3131b]">$</span> python3 -m secure_exam.server{"\n"}
<span className="text-gray-500">[*] TLS socket server  on 127.0.0.1:8443</span>{"\n"}
<span className="text-gray-500">[*] HTTPS JSON API     on {API_URL}/api/v1</span>{"\n"}
<span className="text-gray-500">[*] Web frontend       on {WEB_APP_URL}/</span>{"\n\n"}
<span className="text-[#e3131b]">$</span> python3 -m secure_exam.client --transport https{"\n"}
<span className="text-emerald-400">[+] Authenticated S1001 (Alice Kumar)</span>{"\n"}
<span className="text-emerald-400">[+] Signature Verified: RSA-PSS 3072-bit</span>
            </pre>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="py-12 px-6 border-t border-[#b6b095]/10 text-center font-mono text-xs text-[#b6b095]/50">
        <p>© 2026 Secure Online Examination System · Group CNS Project</p>
        <p className="mt-1 text-[11px]">Powered by Lycoris WebGL Specimen · React · Tailwind CSS · TypeScript · WebCrypto</p>
      </footer>
    </div>
  )
}
