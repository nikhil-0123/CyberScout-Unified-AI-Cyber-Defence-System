import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { KeyRound, Shield, CheckCircle2, XCircle, AlertTriangle, Info, Eye, EyeOff, Sparkles, RefreshCw } from 'lucide-react';

const COMMON_PATTERNS = [
    'password', '123456', '12345678', 'qwerty', 'admin', 'welcome', 'login',
    'iloveyou', 'sunshine', 'princess', 'football', 'charlie', 'monkey'
];

const PasswordSecurity = () => {
    const [password, setPassword] = useState('');
    const [showPassword, setShowPassword] = useState(false);

    // Mathematical Entropy & Strength Evaluation (100% Client-Side)
    const evaluateStrength = (pwd) => {
        if (!pwd) {
            return {
                score: 0,
                entropy: 0,
                tier: 'Empty',
                color: 'text-slate-500',
                bgGradient: 'from-slate-700 to-slate-900',
                crackTime: 'N/A',
                checks: { length: false, lower: false, upper: false, digit: false, special: false, notCommon: true },
                recommendations: ['Enter a password to begin real-time cryptographic strength analysis.']
            };
        }

        const len = pwd.length;
        const hasLower = /[a-z]/.test(pwd);
        const hasUpper = /[A-Z]/.test(pwd);
        const hasDigit = /\d/.test(pwd);
        const hasSpecial = /[^a-zA-Z0-9]/.test(pwd);

        let poolSize = 0;
        if (hasLower) poolSize += 26;
        if (hasUpper) poolSize += 26;
        if (hasDigit) poolSize += 10;
        if (hasSpecial) poolSize += 33;

        // Shannon Entropy approximation: H = L * log2(R)
        const entropy = poolSize > 0 ? Math.round(len * Math.log2(poolSize)) : 0;

        // Check dictionary & repetitive patterns
        const lower = pwd.toLowerCase();
        const hasCommonPattern = COMMON_PATTERNS.some(pat => lower.includes(pat));
        const hasRepeat = /(.)\1{2,}/.test(pwd);
        const hasSequence = /(012|123|234|345|456|567|678|789|abc|bcd|cde|def|qwe|asd)/i.test(pwd);

        const checks = {
            length: len >= 12,
            lower: hasLower,
            upper: hasUpper,
            digit: hasDigit,
            special: hasSpecial,
            notCommon: !hasCommonPattern && !hasRepeat && !hasSequence
        };

        // Score 0 to 100
        let score = 0;
        if (len >= 8) score += 20;
        if (len >= 12) score += 15;
        if (len >= 16) score += 15;
        if (hasLower) score += 10;
        if (hasUpper) score += 10;
        if (hasDigit) score += 10;
        if (hasSpecial) score += 15;
        if (!hasCommonPattern) score += 5;
        if (hasRepeat || hasSequence) score = Math.max(10, score - 20);

        score = Math.min(100, Math.max(5, score));

        // Time to crack estimation (offline high-speed GPU cluster: 100 billion guesses/sec)
        let crackTime = 'Instantly';
        if (entropy > 80) crackTime = 'Tens of thousands of years';
        else if (entropy > 65) crackTime = 'Several centuries';
        else if (entropy > 52) crackTime = 'Several months to years';
        else if (entropy > 40) crackTime = 'A few hours to days';
        else if (entropy > 28) crackTime = 'A few seconds to minutes';

        let tier = 'Weak';
        let color = 'text-rose-400';
        let bgGradient = 'from-rose-600 to-rose-400';
        if (score >= 80) {
            tier = 'Strong (High Entropy)';
            color = 'text-emerald-400';
            bgGradient = 'from-emerald-600 to-emerald-400';
        } else if (score >= 50) {
            tier = 'Moderate';
            color = 'text-amber-400';
            bgGradient = 'from-amber-600 to-amber-400';
        }

        const recommendations = [];
        if (len < 14) recommendations.push('Increase length to 14+ characters, preferably using an unexpected multi-word passphrase.');
        if (!hasSpecial) recommendations.push('Incorporate unpredictable symbols (!@#$%^&*) to expand the character search space.');
        if (!hasUpper || !hasLower) recommendations.push('Mix uppercase and lowercase characters throughout the phrase.');
        if (hasCommonPattern || hasSequence) recommendations.push('Remove sequential numbers, keyboard walks (qwerty), or dictionary words.');
        if (recommendations.length === 0) {
            recommendations.push('Excellent cryptographic variety. Ensure this credential is not reused across multiple services.');
        }

        return { score, entropy, tier, color, bgGradient, crackTime, checks, recommendations };
    };

    const analysis = evaluateStrength(password);

    const generatePassphrase = () => {
        const words = ['cyber', 'scout', 'granite', 'falcon', 'aurora', 'matrix', 'cobalt', 'vortex', 'sentinel', 'quantum', 'prism', 'zenith'];
        const num = Math.floor(100 + Math.random() * 900);
        const sym = ['!', '#', '$', '%', '&', '*'][Math.floor(Math.random() * 6)];
        const pick1 = words[Math.floor(Math.random() * words.length)];
        const pick2 = words[Math.floor(Math.random() * words.length)];
        const pick3 = words[Math.floor(Math.random() * words.length)];
        const phrase = `${pick1.charAt(0).toUpperCase() + pick1.slice(1)}-${pick2}-${num}${sym}-${pick3}`;
        setPassword(phrase);
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
                    <KeyRound className="w-4 h-4" />
                    Zero-Knowledge Local Forensics
                </motion.div>
                <h2 className="text-5xl font-black text-white tracking-tighter uppercase leading-none">
                    Password <span className="text-gradient-emerald">Security</span> Intelligence
                </h2>
                <p className="text-slate-400 text-lg font-medium max-w-2xl">
                    Client-side cryptographic entropy and pattern evaluator. Your credentials are never transmitted, hashed, or stored externally.
                </p>
            </div>

            {/* Input & Evaluation Card */}
            <div className="glass-card p-10 md:p-14 rounded-[3.5rem] border border-white/5 shadow-2xl relative overflow-hidden">
                <div className="space-y-8 relative z-10">
                    <div className="space-y-4">
                        <div className="flex items-center justify-between">
                            <label className="text-xs font-black text-slate-400 uppercase tracking-[0.3em]">
                                Test Credential Input
                            </label>
                            <button
                                type="button"
                                onClick={generatePassphrase}
                                className="inline-flex items-center gap-2 text-xs font-black text-emerald-400 hover:text-emerald-300 transition-colors uppercase tracking-widest"
                            >
                                <Sparkles className="w-4 h-4" />
                                Generate High-Entropy Passphrase
                            </button>
                        </div>

                        <div className="relative group/input">
                            <input
                                type={showPassword ? 'text' : 'password'}
                                value={password}
                                onChange={(e) => setPassword(e.target.value)}
                                className="w-full bg-slate-900/60 border border-white/10 rounded-[2rem] py-6 pl-8 pr-20 text-white placeholder:text-slate-700 focus:outline-none focus:ring-4 focus:ring-emerald-500/10 focus:border-emerald-500/40 transition-all font-mono text-lg font-bold"
                                placeholder="Type or generate a passphrase to evaluate..."
                                autoComplete="off"
                                spellCheck="false"
                            />
                            <button
                                type="button"
                                onClick={() => setShowPassword(!showPassword)}
                                className="absolute right-6 top-1/2 -translate-y-1/2 p-3 text-slate-500 hover:text-white transition-colors"
                            >
                                {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                            </button>
                        </div>
                    </div>

                    {/* Real-time Entropy Meter */}
                    <div className="space-y-4 pt-4 border-t border-white/5">
                        <div className="flex justify-between items-end">
                            <span className="text-xs font-bold text-slate-400 uppercase tracking-widest">
                                Cryptographic Strength: <strong className={analysis.color}>{analysis.tier}</strong>
                            </span>
                            <span className={`text-4xl font-black ${analysis.color}`}>{analysis.score}%</span>
                        </div>
                        <div className="h-4 w-full bg-white/5 rounded-full overflow-hidden p-[2px]">
                            <motion.div
                                initial={{ width: 0 }}
                                animate={{ width: `${analysis.score}%` }}
                                transition={{ duration: 0.5 }}
                                className={`h-full rounded-full bg-gradient-to-r ${analysis.bgGradient}`}
                            />
                        </div>
                    </div>

                    {/* Metric Cards Grid */}
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-6 pt-6">
                        <div className="p-6 glass-card border-white/5 rounded-3xl">
                            <span className="text-[10px] font-black text-slate-500 uppercase tracking-widest block mb-2">Shannon Entropy</span>
                            <span className="text-3xl font-black text-white">{analysis.entropy} <span className="text-xs text-slate-500 font-bold">bits</span></span>
                            <p className="text-[11px] text-slate-400 mt-2 font-medium">Mathematical complexity against brute-force permutations.</p>
                        </div>

                        <div className="p-6 glass-card border-white/5 rounded-3xl">
                            <span className="text-[10px] font-black text-slate-500 uppercase tracking-widest block mb-2">Crack Time Estimate</span>
                            <span className="text-2xl font-black text-emerald-400">{analysis.crackTime}</span>
                            <p className="text-[11px] text-slate-400 mt-2 font-medium">At 100 billion offline GPU computations/sec.</p>
                        </div>

                        <div className="p-6 glass-card border-white/5 rounded-3xl">
                            <span className="text-[10px] font-black text-slate-500 uppercase tracking-widest block mb-2">Length Verification</span>
                            <span className="text-3xl font-black text-white">{password.length} <span className="text-xs text-slate-500 font-bold">chars</span></span>
                            <p className="text-[11px] text-slate-400 mt-2 font-medium">14+ characters recommended for strong protection.</p>
                        </div>
                    </div>

                    {/* Criteria Checklist */}
                    <div className="pt-6 border-t border-white/5">
                        <h4 className="text-xs font-black text-slate-400 uppercase tracking-[0.3em] mb-6">
                            Security Standard Conformance
                        </h4>
                        <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
                            {[
                                { label: 'Length >= 12 chars', pass: analysis.checks.length },
                                { label: 'Lowercase (a-z)', pass: analysis.checks.lower },
                                { label: 'Uppercase (A-Z)', pass: analysis.checks.upper },
                                { label: 'Numeric Digits (0-9)', pass: analysis.checks.digit },
                                { label: 'Special Symbols (!@#$)', pass: analysis.checks.special },
                                { label: 'No Common Patterns', pass: analysis.checks.notCommon },
                            ].map((item, idx) => (
                                <div key={idx} className="flex items-center gap-3 p-4 glass-card border-white/5 rounded-2xl">
                                    {item.pass ? (
                                        <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
                                    ) : (
                                        <XCircle className="w-5 h-5 text-slate-600 shrink-0" />
                                    )}
                                    <span className={`text-xs font-bold ${item.pass ? 'text-white' : 'text-slate-500'}`}>{item.label}</span>
                                </div>
                            ))}
                        </div>
                    </div>

                    {/* Practical Recommendations */}
                    <div className="pt-6 border-t border-white/5">
                        <h4 className="text-xs font-black text-slate-400 uppercase tracking-[0.3em] mb-4">
                            Hardening Recommendations
                        </h4>
                        <ul className="space-y-3">
                            {analysis.recommendations.map((rec, i) => (
                                <li key={i} className="flex items-start gap-3 text-xs font-semibold text-slate-300">
                                    <Shield className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                                    <span>{rec}</span>
                                </li>
                            ))}
                        </ul>
                    </div>

                    {/* Disclaimer Banner */}
                    <div className="p-6 bg-slate-900/60 border border-white/5 rounded-2xl flex items-start gap-4 text-slate-400 text-xs">
                        <Info className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
                        <span>
                            <strong>Security Advisory:</strong> Password strength evaluation is an offline mathematical measure of entropy. No algorithm can guarantee absolute security against social engineering, keyloggers, or breached third-party services. Always activate Multi-Factor Authentication (MFA) across your critical profiles.
                        </span>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default PasswordSecurity;
