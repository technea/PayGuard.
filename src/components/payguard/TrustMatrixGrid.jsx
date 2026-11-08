"use client";
import { useState } from "react";
import { ChevronDown, Globe, FileCode2, Users, ScanSearch, CheckCircle2, AlertTriangle, CircleSlash } from "lucide-react";
import { AnimatePresence, motion } from "framer-motion";

const defaults = [
 {id:"url",title:"URL / Domain Lexical",Icon:Globe},
 {id:"contract",title:"Smart Contract Audit",Icon:FileCode2},
 {id:"counterparty",title:"Counterparty Reputation",Icon:Users},
 {id:"calldata",title:"Calldata / Permit Analysis",Icon:ScanSearch}
];
const styles = {
 VERIFIED:{label:"VERIFIED",icon:CheckCircle2,cls:"border-emerald-500/30 bg-emerald-500/10 text-emerald-300"},
 "HIGH RISK":{label:"HIGH RISK",icon:AlertTriangle,cls:"border-red-500/40 bg-red-500/10 text-red-300"},
 UNAVAILABLE:{label:"UNAVAILABLE",icon:CircleSlash,cls:"border-slate-600 bg-slate-800/70 text-slate-400"}
};
export default function TrustMatrixGrid({ checks = [], className = "" }) {
 const [open,setOpen] = useState(null);
 const rows = defaults.map(d=>({...d,...(checks.find(c=>c.id===d.id)||{}),id:d.id,Icon:d.Icon}));
 return <section className={`w-full min-w-0 rounded-2xl border border-cyan-500/20 bg-slate-950/90 p-4 sm:p-5 ${className}`}>
  <div className="mb-4"><p className="text-xs tracking-[.18em] text-cyan-300">FEDERATED INTELLIGENCE</p><h2 className="mt-1 text-lg font-semibold text-white">Trust matrix</h2><p className="mt-1 text-xs text-slate-500">Unavailable checks are not interpreted as safe.</p></div>
  <div className="grid min-w-0 grid-cols-1 gap-3 sm:grid-cols-2">
   {rows.map(row=>{const status=styles[row.status] ? row.status : "UNAVAILABLE";const BadgeIcon=styles[status].icon;const expanded=open===row.id;
    return <div key={row.id} className="min-w-0 overflow-hidden rounded-xl border border-slate-800 bg-slate-900/70">
     <button type="button" aria-expanded={expanded} onClick={()=>setOpen(expanded?null:row.id)} className="flex w-full min-w-0 items-center gap-3 p-3 text-left hover:bg-slate-800/60 sm:p-4">
      <span className="grid h-9 w-9 shrink-0 place-items-center rounded-lg bg-slate-800 text-cyan-300"><row.Icon size={18}/></span>
      <span className="min-w-0 flex-1"><span className="block break-words text-sm font-semibold text-slate-100">{row.title}</span><span className="mt-1 block text-xs text-slate-500">{row.source ?? "Source not reported"}</span></span>
      <span className={`inline-flex shrink-0 items-center gap-1 rounded-full border px-2 py-1 text-[10px] font-bold tracking-wide ${styles[status].cls}`}><BadgeIcon size={12}/>{styles[status].label}</span>
      <ChevronDown size={16} className={`shrink-0 text-slate-500 transition-transform ${expanded?"rotate-180":""}`}/>
     </button>
     <AnimatePresence initial={false}><motion.div initial={{height:0,opacity:0}} animate={{height:"auto",opacity:1}} exit={{height:0,opacity:0}} transition={{duration:.2}} className="overflow-hidden">
      {expanded && <div className="space-y-2 border-t border-slate-800 px-4 py-3">
       <p className="break-words text-sm text-slate-300">{row.summary ?? "No evidence summary was returned for this check."}</p>
       {(row.metrics ?? []).map((m,i)=><div key={i} className="flex flex-wrap justify-between gap-2 text-xs"><span className="text-slate-500">{m.label}</span><span className="break-all font-mono text-slate-300">{m.value}</span></div>)}
       <div className="flex flex-wrap justify-between gap-2 border-t border-slate-800 pt-2 text-[11px] text-slate-500"><span>{row.source ?? "Source unavailable"}</span><time>{row.timestamp ? new Date(row.timestamp).toLocaleString() : "Timestamp unavailable"}</time></div>
      </div>}
     </motion.div></AnimatePresence>
    </div>
   })}
  </div>
 </section>;
}
