"use client";
import { useState } from "react";
import { ArrowDownRight, ArrowUpRight, Fuel, ShieldAlert, Code2, FileText } from "lucide-react";

const money = (value, unit = "ETH") => `${Number(value).toFixed(6)} ${unit}`;

export default function StateDiffVisualizer({
  sentAssets = [], gasEstimate = "0.000000", gasUsd,
  balanceChanges = [], allowances = [], rawCalldata = "",
  decodedSummary = "No decoded summary available.",
  onRawCalldataChange
}) {
  const [raw, setRaw] = useState(false);
  const toggle = (next) => { setRaw(next); onRawCalldataChange?.(next); };
  return <section className="w-full min-w-0 rounded-2xl border border-cyan-500/25 bg-slate-950/90 p-4 shadow-[0_0_20px_rgba(6,182,212,0.08)] sm:p-5">
    <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
      <div><p className="text-xs font-semibold tracking-[.18em] text-cyan-300">TRANSACTION IMPACT</p><h2 className="mt-1 text-lg font-semibold text-white">State diff analysis</h2></div>
      <div className="inline-flex rounded-lg border border-slate-700 bg-slate-900 p-1" role="group" aria-label="Calldata display">
        <button type="button" onClick={() => toggle(false)} aria-pressed={!raw} className={`rounded-md px-3 py-2 text-xs ${!raw ? "bg-cyan-500/15 text-cyan-200" : "text-slate-400"}`}><FileText size={14} className="mr-1 inline"/>Summary</button>
        <button type="button" onClick={() => toggle(true)} aria-pressed={raw} className={`rounded-md px-3 py-2 text-xs ${raw ? "bg-cyan-500/15 text-cyan-200" : "text-slate-400"}`}><Code2 size={14} className="mr-1 inline"/>Raw hex</button>
      </div>
    </div>
    <div className="grid min-w-0 grid-cols-1 gap-3 md:grid-cols-2">
      <div className="min-w-0 rounded-xl border border-slate-800 bg-slate-900/70 p-4">
        <h3 className="mb-3 flex items-center gap-2 text-sm font-semibold text-slate-200"><Fuel size={16} className="text-cyan-300"/>Sent assets & gas overhead</h3>
        {sentAssets.length ? sentAssets.map((item,i)=><div key={item.id ?? i} className="flex justify-between gap-3 border-b border-slate-800 py-2 text-sm last:border-0"><span className="min-w-0 truncate text-slate-400">{item.label ?? item.symbol ?? "Asset sent"}</span><span className="shrink-0 font-mono text-red-400">−{item.amount} {item.symbol}</span></div>) : <p className="text-sm text-slate-500">No outgoing assets reported.</p>}
        <div className="mt-3 flex items-center justify-between gap-2 border-t border-slate-800 pt-3 text-sm"><span className="text-slate-400" title="Estimated network fee; actual fee may differ">Estimated gas ⓘ</span><span className="font-mono text-amber-300">{money(gasEstimate)}{gasUsd != null && <small className="ml-2 text-slate-500">≈ ${gasUsd} USD</small>}</span></div>
      </div>
      <div className="min-w-0 rounded-xl border border-slate-800 bg-slate-900/70 p-4">
        <h3 className="mb-3 flex items-center gap-2 text-sm font-semibold text-slate-200"><ShieldAlert size={16} className="text-emerald-300"/>Net balance & allowances</h3>
        {balanceChanges.length ? balanceChanges.map((item,i)=><div key={item.id ?? i} className="flex justify-between gap-3 border-b border-slate-800 py-2 text-sm last:border-0"><span className="min-w-0 truncate text-slate-400">{item.label ?? item.symbol}</span><span className={`shrink-0 font-mono ${Number(item.delta) < 0 ? "text-red-400" : "text-emerald-400"}`}>{Number(item.delta)>0?"+":""}{item.delta} {item.symbol}</span></div>) : <p className="text-sm text-slate-500">No balance changes supplied.</p>}
        {allowances.map((item,i)=><div key={item.id ?? i} className="mt-3 rounded-lg border border-amber-500/25 bg-amber-500/5 p-3"><p className="text-xs font-semibold text-amber-300"> {item.unlimited ? "UNLIMITED APPROVAL" : "ALLOWANCE CHANGE"}</p><p className="mt-1 break-all font-mono text-xs text-slate-300">{item.spender ?? "Spender not provided"}</p><p className="mt-1 text-xs text-slate-400">{item.amount ?? (item.unlimited ? "Unlimited allowance" : "Amount unavailable")}</p></div>)}
      </div>
    </div>
    <div className="mt-3 min-w-0 rounded-xl border border-slate-800 bg-[#070d18] p-3">
      <p className="mb-2 text-[11px] font-semibold tracking-wider text-slate-500">{raw ? "RAW CALLDATA HEX" : "DECODED HUMAN SUMMARY"}</p>
      {raw ? <pre className="max-w-full overflow-x-auto whitespace-pre font-mono text-xs leading-6 text-cyan-200 [scrollbar-width:thin]">{rawCalldata || "Calldata unavailable"}</pre> : <p className="whitespace-pre-wrap break-words text-sm text-slate-300">{decodedSummary}</p>}
    </div>
  </section>;
}
