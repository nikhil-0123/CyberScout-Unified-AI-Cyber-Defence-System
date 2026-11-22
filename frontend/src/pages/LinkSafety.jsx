import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { Link2, ShieldCheck, ShieldAlert, AlertTriangle, ExternalLink, CheckCircle2, Lock, Eye, AlertCircle, Info, Radio } from 'lucide-react';
import { analyzeUrl } from '../utils/api';

const LinkSafety = () => {
    const [url, setUrl] = useState('');
    const [loading, setLoading] = useState(false);
    const [result, setResult] = useState(null);
    const [error, setError] = useState('');

    const handleInspect = async (e) => {
        e.preventDefault();
        if (!url) return;

        setLoading(true);
        setError('');
        setResult(null);

        try {
            const user = JSON.parse(localStorage.getItem('cyberscout_currentUser') || localStorage.getItem('phishguard_currentUser') || '{}');
            const res = await analyzeUrl(url, '', user.id);
            setResult(res.data);
        } catch (err) {
            const detail = err.response?.data?.detail;
            setError(detail || 'Inspection failed. Please verify that the target URL format is valid and server is running.');
        } finally {
            setLoading(false);
        }
    };

    const getRiskColor = (tier) => {
        switch (tier?.toUpperCase()) {
            case 'LOW':
                return { badge: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30', bar: 'from-emerald-500 to-emerald-400', icon: ShieldCheck };
            case 'MEDIUM':
                return { badge: 'bg-amber-500/20 text-amber-400 border-amber-500/30', bar: 'from-amber-500 to-amber-400', icon: AlertTriangle };
            case 'HIGH':
                return { badge: 'bg-orange-500/20 text-orange-400 border-orange-500/30', bar: 'from-orange-500 to-orange-400', icon: AlertTriangle };
            case 'CONFIRMED_MALICIOUS':
                return { badge: 'bg-rose-500/20 text-rose-400 border-rose-500/30', bar: 'from-rose-600 to-rose-400', icon: ShieldAlert };
            default:
                return { badge: 'bg-slate-500/20 text-slate-400 border-slate-500/30', bar: 'from-slate-500 to-slate-400', icon: Info };
        }
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
                    <Link2 className="w-4 h-4" />
                    SSRF-Protected Link Safety Inspector
                </motion.div>
                <h2 className="text-5xl font-black text-white tracking-tighter uppercase leading-none">
                    Link <span className="text-gradient-emerald">Safety</span> Verification
                </h2>
                <p className="text-slate-400 text-lg font-medium max-w-2xl">
                    Inspect external destinations before interaction. Evaluates domain structure, protocol authenticity, SSRF boundaries, and corroborated threat signals.
                </p>
            </div>

            {/* Input Card */}
            <div className="glass-card p-10 rounded-[3.5rem] border border-white/5 shadow-2xl relative overflow-hidden">
                <form onSubmit={handleInspect} className="space-y-6">
                    <div className="space-y-3">
                        <label className="text-xs font-black text-slate-400 uppercase tracking-[0.3em] block">
                            Target Link Destination
                        </label>
                        <div className="relative group/input">
                            <input
                                type="url"
                                value={url}
                                onChange={(e) => setUrl(e.target.value)}
                                className="w-full bg-slate-900/60 border border-white/10 rounded-[2rem] py-6 pl-8 pr-10 text-white placeholder:text-slate-700 focus:outline-none focus:ring-4 focus:ring-emerald-500/10 focus:border-emerald-500/40 transition-all font-mono text-base font-bold"
                                placeholder="https://example.com/login"
                                required
                            />
                        </div>
                    </div>

                    <button
                        type="submit"
                        disabled={loading}
                        className="btn-primary w-full py-6 font-black uppercase tracking-[0.2em] text-sm flex items-center justify-center gap-4"
                    >
                        {loading ? (
                            <>
                                <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                                <span>Validating SSRF & Neural Threat Signals...</span>
                            </>
                        ) : (
                            <>
                                <Radio className="w-5 h-5" />
                                <span>Execute Link Forensics</span>
                            </>
                        )}
                    </button>
                </form>

                {error && (
                    <motion.div
                        initial={{ opacity: 0, y: 10 }}
                        animate={{ opacity: 1, y: 0 }}
                        className="mt-6 p-6 bg-red-500/10 border border-red-500/30 rounded-2xl flex items-center gap-4 text-red-400 text-xs font-bold"
                    >
                        <AlertCircle className="w-5 h-5 shrink-0" />
                        <span>{error}</span>
                    </motion.div>
                )}
            </div>

            {/* Inspection Results */}
            {result && (
                <motion.div
                    initial={{ opacity: 0, scale: 0.98 }}
                    animate={{ opacity: 1, scale: 1 }}
                    className="glass-card p-10 md:p-14 rounded-[3.5rem] border border-white/5 shadow-2xl space-y-10"
                >
                    {/* Header Verdict */}
                    <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-6 pb-8 border-b border-white/5">
                        <div className="space-y-2">
                            <span className="text-[10px] font-black text-slate-500 uppercase tracking-widest block">Inspection Outcome</span>
                            <h3 className="text-3xl font-black text-white tracking-tight uppercase">
                                Classification: <span className={result.prediction === 'phishing' ? 'text-rose-400' : 'text-emerald-400'}>{result.prediction}</span>
                            </h3>
                            <p className="text-xs font-mono text-slate-400 break-all">{result.url}</p>
                        </div>

                        <div className="flex items-center gap-3">
                            <span className={`px-5 py-2.5 rounded-2xl border text-xs font-black uppercase tracking-widest ${getRiskColor(result.risk_level).badge}`}>
                                Risk Tier: {result.risk_level || 'EVALUATED'}
                            </span>
                            {result.is_trusted_domain && (
                                <span className="px-5 py-2.5 rounded-2xl border bg-emerald-500/10 border-emerald-500/30 text-emerald-400 text-xs font-black uppercase tracking-widest flex items-center gap-2">
                                    <ShieldCheck className="w-4 h-4" />
                                    Verified Allowlist
                                </span>
                            )}
                        </div>
                    </div>

                    {/* Threat Score Gauge */}
                    <div className="space-y-4">
                        <div className="flex justify-between items-end">
                            <span className="text-xs font-black text-slate-400 uppercase tracking-widest">
                                Unified Threat Assessment Score
                            </span>
                            <span className="text-4xl font-black text-white">{result.risk_score}%</span>
                        </div>
                        <div className="h-4 w-full bg-white/5 rounded-full overflow-hidden p-[2px]">
                            <motion.div
                                initial={{ width: 0 }}
                                animate={{ width: `${result.risk_score}%` }}
                                transition={{ duration: 0.8 }}
                                className={`h-full rounded-full bg-gradient-to-r ${getRiskColor(result.risk_level).bar}`}
                            />
                        </div>
                    </div>

                    {/* Corroborating Signals */}
                    <div className="space-y-4">
                        <h4 className="text-xs font-black text-slate-400 uppercase tracking-[0.3em] flex items-center gap-2">
                            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                            Multi-Signal Corroboration (Decision 3 Policy)
                        </h4>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                            {result.corroborating_signals && result.corroborating_signals.length > 0 ? (
                                result.corroborating_signals.map((sig, idx) => (
                                    <div key={idx} className="p-5 glass-card border-white/5 rounded-2xl text-xs font-semibold text-slate-200 flex items-start gap-3">
                                        <div className="w-2 h-2 rounded-full bg-emerald-400 shrink-0 mt-1.5 shadow-[0_0_8px_#34d399]" />
                                        <span>{sig}</span>
                                    </div>
                                ))
                            ) : (
                                <div className="p-5 glass-card border-white/5 rounded-2xl text-xs text-slate-500 font-bold col-span-2">
                                    No corroborating high-severity indicators isolated.
                                </div>
                            )}
                        </div>
                    </div>

                    {/* Reasons & Evidence */}
                    <div className="space-y-4">
                        <h4 className="text-xs font-black text-slate-400 uppercase tracking-[0.3em]">
                            Forensic Telemetry & Audit Notes
                        </h4>
                        <ul className="space-y-3">
                            {result.reasons?.map((r, i) => (
                                <li key={i} className="p-4 bg-slate-900/40 border border-white/5 rounded-2xl text-xs text-slate-300 font-medium flex items-center gap-3">
                                    <span className="w-1.5 h-1.5 rounded-full bg-slate-500" />
                                    <span>{r}</span>
                                </li>
                            ))}
                        </ul>
                    </div>

                    {/* Enforcement Verdict */}
                    <div className="p-6 bg-slate-900/80 border border-white/10 rounded-2xl flex items-center justify-between">
                        <div>
                            <span className="text-[10px] font-black text-slate-500 uppercase tracking-widest block">Action Policy</span>
                            <span className="text-lg font-black text-white uppercase tracking-wider">{result.action || 'MONITOR'}</span>
                        </div>
                        <div className="text-right">
                            <span className="text-[10px] font-black text-slate-500 uppercase tracking-widest block">Auto-Block Status</span>
                            <span className={`text-sm font-black uppercase tracking-wider ${result.auto_blocked ? 'text-rose-400' : 'text-emerald-400'}`}>
                                {result.auto_blocked ? 'Active in Registry' : 'Not Blocked (Safe / Warning)'}
                            </span>
                        </div>
                    </div>
                </motion.div>
            )}
        </div>
    );
};

export default LinkSafety;
