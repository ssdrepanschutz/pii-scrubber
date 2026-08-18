from __future__ import annotations

import os
import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from PIL import Image, ImageTk
from io import BytesIO

from engine import (
    APP_VERSION, ExportOptions, ScanOptions, SecureCheckpoint, dedupe_entity_replacements,
    export_sanitized, preview_page, scan_document, suggest_output_path,
)


class PIIScrubberApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"Local PII Scrubber v{APP_VERSION}")
        self.geometry("1320x820")
        self.minsize(1100, 700)
        self.input_path = ""
        self.findings = []
        self.page_modes = {}
        self.preview_img = None
        self.q = queue.Queue()
        self._build()
        self.after(100, self._poll)

    def _build(self):
        top = ttk.Frame(self, padding=10); top.pack(fill="x")
        ttk.Label(top, text=f"Local PII Scrubber v{APP_VERSION}", font=("Segoe UI", 18, "bold")).grid(row=0, column=0, sticky="w")
        ttk.Label(top, text="Large-file mode: chunked scan, selective OCR, sanitization, verification, selective rasterization.").grid(row=1, column=0, columnspan=7, sticky="w", pady=(2, 8))
        self.path_var = tk.StringVar(); ttk.Entry(top, textvariable=self.path_var).grid(row=2, column=0, columnspan=5, sticky="ew", padx=(0, 6))
        ttk.Button(top, text="Open PDF", command=self.open_pdf).grid(row=2, column=5, padx=3); ttk.Button(top, text="Scan / Resume", command=self.scan).grid(row=2, column=6, padx=3); top.columnconfigure(0, weight=1)
        opts = ttk.Frame(top); opts.grid(row=3, column=0, columnspan=7, sticky="ew", pady=(8, 0))
        self.chunk_var=tk.IntVar(value=100); self.ocr_var=tk.BooleanVar(value=True); self.names_var=tk.BooleanVar(value=True); self.addr_var=tk.BooleanVar(value=True); self.custom_var=tk.StringVar(); self.fast_var=tk.BooleanVar(value=True)
        ttk.Checkbutton(opts,text="Fast OCR-PDF Mode",variable=self.fast_var,command=self._fast_mode_changed).pack(side="left",padx=(0,12))
        ttk.Label(opts,text="Chunk pages:").pack(side="left"); ttk.Spinbox(opts,from_=25,to=500,increment=25,width=6,textvariable=self.chunk_var).pack(side="left",padx=(4,12))
        ttk.Checkbutton(opts,text="Selective OCR",variable=self.ocr_var).pack(side="left",padx=4); ttk.Checkbutton(opts,text="Detect names",variable=self.names_var).pack(side="left",padx=4); ttk.Checkbutton(opts,text="Detect addresses",variable=self.addr_var).pack(side="left",padx=4)
        ttk.Label(opts,text="Custom terms:").pack(side="left",padx=(12,4)); ttk.Entry(opts,textvariable=self.custom_var,width=38).pack(side="left",fill="x",expand=True)
        self._fast_mode_changed()
        body=ttk.Panedwindow(self,orient="horizontal"); body.pack(fill="both",expand=True,padx=10,pady=6); left=ttk.Frame(body); right=ttk.Frame(body); body.add(left,weight=3); body.add(right,weight=2)
        cols=("use","page","category","source","confidence","replacement","value"); self.tree=ttk.Treeview(left,columns=cols,show="headings",selectmode="browse")
        labels={"use":"Use","page":"Page","category":"Category","source":"Source","confidence":"Conf.","replacement":"Replacement","value":"Detected value"}; widths={"use":44,"page":58,"category":120,"source":65,"confidence":58,"replacement":135,"value":260}
        for c in cols: self.tree.heading(c,text=labels[c]); self.tree.column(c,width=widths[c],anchor="w")
        y=ttk.Scrollbar(left,orient="vertical",command=self.tree.yview); self.tree.configure(yscrollcommand=y.set); self.tree.pack(side="left",fill="both",expand=True); y.pack(side="right",fill="y"); self.tree.bind("<<TreeviewSelect>>",self.on_select); self.tree.bind("<Double-1>",self.toggle_selected)
        tools=ttk.Frame(right); tools.pack(fill="x",pady=(0,5)); ttk.Button(tools,text="Toggle Finding",command=self.toggle_selected).pack(side="left",padx=2); ttk.Button(tools,text="Select All",command=lambda:self.set_all(True)).pack(side="left",padx=2); ttk.Button(tools,text="Select None",command=lambda:self.set_all(False)).pack(side="left",padx=2); ttk.Button(tools,text="Stable Entity Tokens",command=self.assign_tokens).pack(side="left",padx=2)
        edit=ttk.Frame(right); edit.pack(fill="x",pady=(0,5)); ttk.Label(edit,text="Replacement:").pack(side="left"); self.repl_var=tk.StringVar(); ttk.Entry(edit,textvariable=self.repl_var).pack(side="left",fill="x",expand=True,padx=4); ttk.Button(edit,text="Apply",command=self.apply_replacement).pack(side="left")
        self.canvas=tk.Canvas(right,bg="#666666",highlightthickness=0); self.canvas.pack(fill="both",expand=True)
        export=ttk.LabelFrame(self,text="Verified Export",padding=8); export.pack(fill="x",padx=10,pady=(2,6)); self.mode_var=tk.StringVar(value="tokens"); self.raster_var=tk.BooleanVar(value=True); self.search_var=tk.BooleanVar(value=True)
        ttk.Radiobutton(export,text="Replacement tokens",variable=self.mode_var,value="tokens").pack(side="left"); ttk.Radiobutton(export,text="Black redaction",variable=self.mode_var,value="black").pack(side="left",padx=(4,12)); ttk.Checkbutton(export,text="Rasterize only failed pages",variable=self.raster_var).pack(side="left",padx=4); ttk.Checkbutton(export,text="Restore search on rasterized pages",variable=self.search_var).pack(side="left",padx=4); ttk.Button(export,text="Scrub + Verify + Export",command=self.export).pack(side="right")
        status=ttk.Frame(self,padding=(10,0,10,10)); status.pack(fill="x"); self.progress=ttk.Progressbar(status,mode="determinate"); self.progress.pack(fill="x"); self.status_var=tk.StringVar(value="Ready"); ttk.Label(status,textvariable=self.status_var).pack(anchor="w",pady=(3,0))

    def _fast_mode_changed(self):
        if self.fast_var.get():
            self.chunk_var.set(250)
            self.ocr_var.set(True)
            if hasattr(self, "status_var"): self.status_var.set("Fast OCR-PDF Mode: existing searchable text first; OCR only when needed; 250-page chunks.")

    def checkpoint_path(self):
        if not self.input_path:return ""
        p=Path(self.input_path); return str(p.parent/("."+p.name+".pii-v3.checkpoint"))
    def open_pdf(self):
        p=filedialog.askopenfilename(filetypes=[("PDF files","*.pdf")])
        if p:self.input_path=p;self.path_var.set(p);self.findings=[];self.page_modes={};self._refresh_tree();self.status_var.set("PDF loaded. Scan when ready.")
    def _progress_cb(self,stage,current,total):self.q.put(("progress",stage,current,total))
    def scan(self):
        p=self.path_var.get().strip()
        if not p or not os.path.exists(p):messagebox.showerror("PII Scrubber","Choose a PDF first.");return
        self.input_path=p; custom=[x.strip() for x in self.custom_var.get().split(";") if x.strip()]; opts=ScanOptions(chunk_size=self.chunk_var.get(),selective_ocr=self.ocr_var.get(),detect_names=self.names_var.get(),detect_addresses=self.addr_var.get(),custom_terms=custom,fast_ocr_pdf=self.fast_var.get());self.status_var.set("Fast scanning existing OCR text..." if self.fast_var.get() else "Scanning...");threading.Thread(target=self._scan_worker,args=(opts,),daemon=True).start()
    def _scan_worker(self,opts):
        try:self.q.put(("scan_done",*scan_document(self.input_path,opts,self.checkpoint_path(),self._progress_cb)))
        except Exception as e:self.q.put(("error",f"Scan failed: {e}"))
    def _refresh_tree(self):
        for i in self.tree.get_children():self.tree.delete(i)
        for idx,f in enumerate(self.findings):
            display=f.value if f.category!="SSN" else "***-**-"+"".join(ch for ch in f.value if ch.isdigit())[-4:];self.tree.insert("","end",iid=str(idx),values=("Yes" if f.selected else "No",f.page,f.category,f.source,f"{f.confidence:.2f}",f.replacement,display))
    def set_all(self,flag):
        for f in self.findings:f.selected=flag
        self._refresh_tree()
    def toggle_selected(self,event=None):
        sel=self.tree.selection()
        if not sel:return
        idx=int(sel[0]);self.findings[idx].selected=not self.findings[idx].selected;self._refresh_tree();self.tree.selection_set(str(idx))
    def assign_tokens(self):dedupe_entity_replacements(self.findings);self._refresh_tree();self.status_var.set("Stable provider/person tokens assigned. Claimant remains [CLAIMANT].")
    def apply_replacement(self):
        sel=self.tree.selection()
        if not sel:return
        idx=int(sel[0]);repl=self.repl_var.get().strip()
        if repl:self.findings[idx].replacement=repl;self._refresh_tree();self.tree.selection_set(str(idx))
    def on_select(self,event=None):
        sel=self.tree.selection()
        if not sel or not self.input_path:return
        idx=int(sel[0]);f=self.findings[idx];self.repl_var.set(f.replacement)
        try:
            data=preview_page(self.input_path,f.page,self.findings);im=Image.open(BytesIO(data));im.thumbnail((max(300,self.canvas.winfo_width()-20),max(300,self.canvas.winfo_height()-20)));self.preview_img=ImageTk.PhotoImage(im);self.canvas.delete("all");self.canvas.create_image(10,10,image=self.preview_img,anchor="nw")
        except Exception as e:self.status_var.set(f"Preview unavailable: {e}")
    def export(self):
        if not self.input_path or not self.findings:messagebox.showerror("PII Scrubber","Scan and review the PDF first.");return
        suggested=suggest_output_path(self.input_path);out=filedialog.asksaveasfilename(defaultextension=".pdf",initialfile=Path(suggested).name,filetypes=[("PDF files","*.pdf")])
        if not out:return
        if os.path.abspath(out)==os.path.abspath(self.input_path):messagebox.showerror("PII Scrubber","The scrubbed file cannot overwrite the original.");return
        opts=ExportOptions(chunk_size=self.chunk_var.get(),mode=self.mode_var.get(),sanitize=True,selective_rasterize_on_failure=self.raster_var.get(),restore_search_on_rasterized_pages=self.search_var.get(),fast_ocr_pdf=self.fast_var.get());self.status_var.set("Fast scrub + verify..." if self.fast_var.get() else "Scrubbing, sanitizing, and independently verifying...");threading.Thread(target=self._export_worker,args=(out,opts),daemon=True).start()
    def _export_worker(self,out,opts):
        try:self.q.put(("export_done",export_sanitized(self.input_path,out,self.findings,self.page_modes,opts,self._progress_cb)))
        except Exception as e:self.q.put(("error",f"Export failed: {e}"))
    def _poll(self):
        try:
            while True:
                msg=self.q.get_nowait()
                if msg[0]=="progress":_,stage,current,total=msg;self.progress["maximum"]=max(1,total);self.progress["value"]=current;self.status_var.set(f"{stage.replace('_',' ').title()}: {current}/{total}")
                elif msg[0]=="scan_done":_,self.findings,self.page_modes=msg;self._refresh_tree();failed_ocr=sum(1 for m in self.page_modes.values() if m=="ocr_failed");self.status_var.set(f"Scan complete: {len(self.findings)} findings. OCR review pages: {failed_ocr}.")
                elif msg[0]=="export_done":
                    result=msg[1];review=result["audit"]["pages_requiring_review"];doc_review=result["audit"].get("document_review_required",False)
                    if review or doc_review:self.status_var.set(f"Export created; review required. Page flags: {len(review)}. See audit manifest.");messagebox.showwarning("Review required",f"Export created, but automated verification did not receive a clean document-level PASS.\n\nPage flags: {len(review)}\nPDF: {result['output_path']}\nAudit: {result['audit_path']}")
                    else:self.status_var.set("Verified export complete. Final visual review is still required.");messagebox.showinfo("Export complete",f"All processed pages passed automated verification.\n\nPDF: {result['output_path']}\nAudit: {result['audit_path']}\n\nPerform a final visual review before release.")
                elif msg[0]=="error":self.status_var.set(msg[1]);messagebox.showerror("PII Scrubber",msg[1])
        except queue.Empty:pass
        self.after(100,self._poll)

if __name__=="__main__":PIIScrubberApp().mainloop()
