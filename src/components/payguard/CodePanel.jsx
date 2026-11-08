"use client";
import { useMemo, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { Braces, Check, Copy, Maximize2, Minimize2, X } from "lucide-react";

export default function CodePanel({title="Technical evidence",value="",language="text",className=""}) {
 const [copied,setCopied]=useState(false),[expanded,setExpanded]=useState(false),[pretty,setPretty]=useState(true),[error,setError]=useState("");
 const displayed=useMemo(()=>{if(language!=="json")return String(value??"");try{return pretty?JSON.stringify(JSON.parse(value),null,2):JSON.stringify(JSON.parse(value));}catch{return String(value??"");}},[value,language,pretty]);
 async function copy(){try{await navigator.clipboard.writeText(displayed);setCopied(true);setError("");window.setTimeout(()=>setCopied(false),1600);}catch{setError("Clipboard unavailable. Select the text to copy.");}}
 const actions=<div className="flex flex-wrap items-center gap-2">
  {language==="json"&&<button type="button" onClick={()=>setPretty(v=>!v)} className="rounded-md border border-slate-700 px-3 py-2 text-xs text-slate-300 hover:border-cyan-500">{pretty?"Minify":"Format"} JSON</button>}
  <button type="button" onClick={copy} className="inline-flex items-center gap-1.5 rounded-md border border-cyan-500/30 px-3 py-2 text-xs text-cyan-200 hover:bg-cyan-500/10">{copied?<Check size={14}/>:<Copy size={14}/>} {copied?"Copied":"Copy"}</button>
  <button type="button" onClick={()=>setExpanded(true)} aria-label="Expand code" className="rounded-md border border-slate-700 p-2 text-slate-300 hover:text-cyan-200"><Maximize2 size={14}/></button>
 </div>;
 const pane=<div className="min-w-0 overflow-hidden rounded-xl border border-slate-700/80 bg-[#070d18]">
  <header className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 bg-slate-900/90 px-3 py-3 sm:px-4"><div className="flex min-w-0 items-center gap-2"><Braces size={16} className="shrink-0 text-cyan-300"/><span className="truncate text-sm font-semibold text-slate-200">{title}</span><span className="rounded border border-slate-700 px-2 py-0.5 text-[10px] uppercase text-slate-500">{language}</span></div>{actions}</header>
  {error&&<p role="alert" className="px-4 pt-2 text-xs text-amber-300">{error}</p>}
  <pre className="max-h-[420px] w-full min-w-0 overflow-x-auto overscroll-x-contain p-4 font-mono text-xs leading-6 text-cyan-100 [scrollbar-width:thin]"><code>{displayed}</code></pre>
 </div>;
 return <div className={`w-full min-w-0 ${className}`}>{pane}
 <AnimatePresence>{expanded&&<motion.div initial={{opacity:0}} animate={{opacity:1}} exit={{opacity:0}} className="fixed inset-0 z-[100] flex items-center justify-center bg-black/80 p-3 backdrop-blur-sm sm:p-6" role="dialog" aria-modal="true" aria-label={title} onMouseDown={e=>{if(e.target===e.currentTarget)setExpanded(false);}} onKeyDown={e=>{if(e.key==="Escape")setExpanded(false);}} tabIndex={-1}>
  <motion.div initial={{scale:.97,y:12}} animate={{scale:1,y:0}} exit={{scale:.98}} className="flex max-h-[92dvh] w-full max-w-6xl flex-col overflow-hidden rounded-xl border border-cyan-500/30 bg-slate-950 shadow-2xl">
   <header className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 p-4"><h2 className="font-semibold text-white">{title}</h2><div className="flex items-center gap-2">{actions}<button type="button" onClick={()=>setExpanded(false)} aria-label="Close" className="rounded-md border border-slate-700 p-2 text-slate-300"><X size={15}/></button></div></header>
   <pre className="min-h-0 w-full min-w-0 overflow-auto p-4 font-mono text-xs leading-6 text-cyan-100"><code>{displayed}</code></pre>
  </motion.div>
 </motion.div>}</AnimatePresence></div>;
}
