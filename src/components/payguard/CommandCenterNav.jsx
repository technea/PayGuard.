"use client";
import { useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { Menu, X, Shield, Wallet } from "lucide-react";

export default function CommandCenterNav({brand="PayGuard",links=[],network="BASE MAINNET · 8453",walletLabel="Connect wallet",onWalletClick}) {
 const [open,setOpen]=useState(false);
 return <header className="sticky top-0 z-50 w-full border-b border-cyan-500/20 bg-slate-950/90 backdrop-blur-xl">
  <div className="mx-auto flex h-16 max-w-7xl items-center justify-between gap-3 px-4 sm:px-6">
   <a href="/" className="flex min-w-0 items-center gap-2 text-white"><span className="grid h-9 w-9 shrink-0 place-items-center rounded-xl border border-cyan-400/40 bg-cyan-400/10 text-cyan-300"><Shield size={21}/></span><span className="truncate text-lg font-bold">{brand}</span></a>
   <div className="hidden items-center gap-5 md:flex"><span className="text-[10px] tracking-widest text-emerald-300">{network}</span>{links.map(l=><a key={l.href} href={l.href} className="text-sm text-slate-400 transition hover:text-cyan-200">{l.label}</a>)}<button type="button" onClick={onWalletClick} className="inline-flex items-center gap-2 rounded-lg border border-cyan-500/30 px-3 py-2 text-sm text-cyan-200"><Wallet size={15}/>{walletLabel}</button></div>
   <button type="button" onClick={()=>setOpen(v=>!v)} aria-expanded={open} aria-label={open?"Close menu":"Open menu"} className="inline-flex items-center gap-2 rounded-lg border border-cyan-500/30 px-3 py-2 text-sm text-cyan-100 md:hidden">{open?<X size={18}/>:<Menu size={18}/>}Menu</button>
  </div>
  <AnimatePresence>{open&&<><motion.button aria-label="Close navigation backdrop" initial={{opacity:0}} animate={{opacity:1}} exit={{opacity:0}} onClick={()=>setOpen(false)} className="fixed inset-0 top-16 z-40 h-[calc(100dvh-4rem)] w-full bg-black/60 backdrop-blur-sm md:hidden"/><motion.nav initial={{x:"100%"}} animate={{x:0}} exit={{x:"100%"}} transition={{type:"spring",damping:26,stiffness:240}} className="absolute right-0 top-16 z-50 flex w-[min(88vw,360px)] flex-col gap-2 border-b border-l border-cyan-500/20 bg-slate-950 p-5 shadow-2xl md:hidden"><span className="mb-2 text-[10px] tracking-widest text-emerald-300">{network}</span>{links.map(l=><a key={l.href} href={l.href} onClick={()=>setOpen(false)} className="rounded-lg px-3 py-3 text-sm text-slate-200 hover:bg-slate-800">{l.label}</a>)}<button type="button" onClick={()=>{setOpen(false);onWalletClick?.();}} className="mt-2 inline-flex items-center justify-center gap-2 rounded-lg border border-cyan-500/30 px-3 py-3 text-sm text-cyan-200"><Wallet size={16}/>{walletLabel}</button></motion.nav></>}</AnimatePresence>
 </header>;
}
