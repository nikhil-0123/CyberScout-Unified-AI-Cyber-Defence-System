import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { ShieldAlert, BookOpen, AlertCircle, CheckCircle2, ChevronRight, Eye, Lock, FileWarning, HelpCircle } from 'lucide-react';

const THREAT_TOPICS = [
    {
        id: 'brand-impersonation',
        title: 'Brand Impersonation & Clone Phishing',
        tag: 'High Frequency',
        summary: 'Attackers create near-identical copies of legitimate platforms (PayPal, Google, Microsoft, Banks) to harvest login credentials.',
        signals: [
            'Slightly misspelled or lookalike domain names (e.g., paypa1.com, micros0ft.com)',
            'Generic salutations ("Dear Customer", "Valued Member") instead of your real name',
            'Inconsistent sender address differing from the claimed organization domain'
        ],
        defense: 'Always check the exact root domain in your browser address bar. Bookmark critical banking and work portals rather than clicking email links.'
    },
    {
        id: 'artificial-urgency',
        title: 'Artificial Urgency & Fear Appeals',
        tag: 'Psychological Coercion',
        summary: 'Phishers pressure victims into hurried action by threatening account suspension, legal action, or fraudulent transaction charges within a tight deadline (e.g. "within 24 hours").',
        signals: [
            'Language like "Immediate Action Required" or "Your profile will be terminated today"',
            'Demands for immediate PIN, password, or OTP verification',
            'Unsolicited payment confirmation notices for services you never ordered'
        ],
        defense: 'Take a step back. Legitimate financial institutions and technology providers do not give panic deadlines demanding immediate password input via an unverified link.'
    },
    {
        id: 'typosquatting-masking',
        title: 'Typosquatting & Deceptive URL Structures',
        tag: 'Technical Masking',
        summary: 'Cybercriminals exploit typographical errors, excessive hyphens, or deep subdomains to mislead users into believing a fake site is legitimate.',
        signals: [
            'IP addresses instead of registered domain names (e.g., http://192.168.1.50/login)',
            'Multiple deceptive subdomains (e.g., secure.login.bank.example-phish.com)',
            'Use of the "@" symbol in URLs to mask the true destination authority'
        ],
        defense: 'Examine the portion immediately preceding the top-level domain (TLD). Only the root domain defines where your connection terminates.'
    },
    {
        id: 'credential-harvesting',
        title: 'External Form Credential Harvesting',
        tag: 'Data Exfiltration',
        summary: 'A deceptive webpage renders an authentication form whose HTML action parameter posts submitted passwords to a hidden third-party collection endpoint.',
        signals: [
            'Login prompt appearing unexpectedly on an unsecured (HTTP) page',
            'Form action transmitting submitted inputs to a different external domain',
            'Password field embedded in an iframe or third-party web widget'
        ],
        defense: 'CyberScout automatically inspects form targets and detects mismatched action destinations in its Link Safety module.'
    }
];

const SecurityAwareness = () => {
    const [selectedTopic, setSelectedTopic] = useState(THREAT_TOPICS[0]);
    const [checklist, setChecklist] = useState({
        checkSender: false,
        checkDomain: false,
        avoidUrgency: false,
        verifyMFA: false
    });

    const toggleCheck = (key) => {
        setChecklist({ ...checklist, [key]: !checklist[key] });
    };

    return (
        <div className="max-w-5xl mx-auto space-y-12 py-8 relative animate-fade-in text-white">
            {/* Header */}
            <div className="text-center md:text-left space-y-4">
                <motion.div
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    className="inline-flex items-center gap-3 px-5 py-2 rounded-full glass-card border-white/10 text-emerald-400 text-[10px] font-black uppercase tracking-[0.3em] shadow-xl"
                >
                    <BookOpen className="w-4 h-4" />
                    Threat Intelligence Briefing
                </motion.div>
                <h2 className="text-5xl font-black text-white tracking-tighter uppercase leading-none">
                    Security <span className="text-gradient-emerald">Awareness</span> Briefing
                </h2>
                <p className="text-slate-400 text-lg font-medium max-w-2xl">
                    Understand modern social engineering vectors, technical evasion methods, and verified counter-measures to maintain organizational resilience.
                </p>
            </div>

            {/* Interactive Threat Matrix */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                {/* Topic Selector List */}
                <div className="space-y-4">
                    <span className="text-[10px] font-black text-slate-500 uppercase tracking-widest block pl-2">
                        Common Attack Vectors
                    </span>
                    {THREAT_TOPICS.map((topic) => (
                        <div
                            key={topic.id}
                            onClick={() => setSelectedTopic(topic)}
                            className={`p-6 rounded-3xl border transition-all cursor-pointer ${
                                selectedTopic.id === topic.id
                                    ? 'glass-card border-emerald-500/40 bg-emerald-500/5 shadow-xl'
                                    : 'glass-card border-white/5 hover:border-white/10 opacity-70 hover:opacity-100'
                            }`}
                        >
                            <div className="flex items-center justify-between mb-2">
                                <span className="text-[10px] font-black uppercase tracking-wider text-emerald-400">{topic.tag}</span>
                                <ChevronRight className="w-4 h-4 text-slate-500" />
                            </div>
                            <h4 className="font-bold text-sm text-white">{topic.title}</h4>
                        </div>
                    ))}
                </div>

                {/* Topic Detail View */}
                <div className="lg:col-span-2 glass-card p-10 md:p-12 rounded-[3.5rem] border border-white/5 shadow-2xl space-y-8">
                    <div className="space-y-3 pb-6 border-b border-white/5">
                        <span className="text-[10px] font-black uppercase tracking-widest text-emerald-400">Tactical Vector Briefing</span>
                        <h3 className="text-3xl font-black text-white tracking-tight">{selectedTopic.title}</h3>
                        <p className="text-sm text-slate-300 leading-relaxed font-medium">{selectedTopic.summary}</p>
                    </div>

                    {/* Threat Indicators */}
                    <div className="space-y-4">
                        <h4 className="text-xs font-black text-slate-400 uppercase tracking-[0.3em] flex items-center gap-2">
                            <FileWarning className="w-4 h-4 text-amber-400" />
                            Suspicious Telemetry Indicators
                        </h4>
                        <ul className="space-y-3">
                            {selectedTopic.signals.map((sig, i) => (
                                <li key={i} className="p-4 bg-slate-900/60 border border-white/5 rounded-2xl text-xs font-semibold text-slate-200 flex items-start gap-3">
                                    <span className="w-2 h-2 rounded-full bg-amber-400 shrink-0 mt-1 shadow-[0_0_8px_#fbbf24]" />
                                    <span>{sig}</span>
                                </li>
                            ))}
                        </ul>
                    </div>

                    {/* Practical Countermeasure */}
                    <div className="p-6 bg-emerald-500/10 border border-emerald-500/30 rounded-2xl space-y-2">
                        <h5 className="text-xs font-black text-emerald-400 uppercase tracking-widest flex items-center gap-2">
                            <Lock className="w-4 h-4" />
                            Recommended CyberScout Defense
                        </h5>
                        <p className="text-xs text-slate-300 font-medium leading-relaxed">{selectedTopic.defense}</p>
                    </div>
                </div>
            </div>

            {/* Quick Interactive Verification Checklist */}
            <div className="glass-card p-10 rounded-[3.5rem] border border-white/5 shadow-2xl space-y-6">
                <div className="flex items-center gap-3">
                    <CheckCircle2 className="w-6 h-6 text-emerald-400" />
                    <div>
                        <h4 className="text-xl font-black text-white uppercase tracking-tight">Interactive Suspicious Message Triage</h4>
                        <p className="text-xs text-slate-400 font-medium">Verify each security check before opening any external link or entering credentials.</p>
                    </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-4">
                    {[
                        { key: 'checkSender', label: 'Sender authenticity confirmed via genuine organization domain' },
                        { key: 'checkDomain', label: 'Root domain matches destination without deceptive subdomains' },
                        { key: 'avoidUrgency', label: 'No artificial panic deadline or demand for immediate credential input' },
                        { key: 'verifyMFA', label: 'Multi-Factor Authentication active on target profile' },
                    ].map((item) => (
                        <div
                            key={item.key}
                            onClick={() => toggleCheck(item.key)}
                            className={`p-5 rounded-2xl border cursor-pointer transition-all flex items-center gap-4 ${
                                checklist[item.key]
                                    ? 'bg-emerald-500/10 border-emerald-500/40 text-white'
                                    : 'bg-slate-900/40 border-white/5 text-slate-400 hover:border-white/10'
                            }`}
                        >
                            <input
                                type="checkbox"
                                checked={checklist[item.key]}
                                onChange={() => {}}
                                className="w-5 h-5 accent-emerald-500 rounded cursor-pointer"
                            />
                            <span className="text-xs font-bold">{item.label}</span>
                        </div>
                    ))}
                </div>
            </div>
        </div>
    );
};

export default SecurityAwareness;
