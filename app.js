const $ = id => document.getElementById(id);
const drop = $("drop"), results = $("results"), progress = $("progress"), summary = $("summary");
const DB = new Map(window.DATABASE.map(e => [e.sha256.toLowerCase(), e]));

// ---------- SHA-256 ----------
const hex = buf => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");

// Запасной SHA-256 на чистом JS (если crypto.subtle недоступен), читает файл кусками
const K = new Uint32Array([0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]);
class Sha256 {
  constructor(){ this.h = new Uint32Array([0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]); this.buf = new Uint8Array(64); this.n = 0; this.len = 0; this.w = new Uint32Array(64); }
  block(b, o){
    const w = this.w, h = this.h, r = (x,n)=>(x>>>n)|(x<<(32-n));
    for(let i=0;i<16;i++) w[i]=(b[o+4*i]<<24)|(b[o+4*i+1]<<16)|(b[o+4*i+2]<<8)|b[o+4*i+3];
    for(let i=16;i<64;i++){ const a=w[i-15], c=w[i-2]; w[i]=(w[i-16]+(r(a,7)^r(a,18)^(a>>>3))+w[i-7]+(r(c,17)^r(c,19)^(c>>>10)))|0; }
    let [a,b2,c,d,e,f,g,hh]=h;
    for(let i=0;i<64;i++){
      const t1=(hh+(r(e,6)^r(e,11)^r(e,25))+((e&f)^(~e&g))+K[i]+w[i])|0;
      const t2=((r(a,2)^r(a,13)^r(a,22))+((a&b2)^(a&c)^(b2&c)))|0;
      hh=g;g=f;f=e;e=(d+t1)|0;d=c;c=b2;b2=a;a=(t1+t2)|0;
    }
    h[0]+=a;h[1]+=b2;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
  }
  update(data){
    this.len += data.length; let i = 0;
    if(this.n){ while(i<data.length && this.n<64) this.buf[this.n++]=data[i++]; if(this.n===64){ this.block(this.buf,0); this.n=0; } }
    while(i+64<=data.length){ this.block(data,i); i+=64; }
    while(i<data.length) this.buf[this.n++]=data[i++];
  }
  digest(){
    const bits = this.len*8, pad = new Uint8Array(((this.n<56)?56:120)-this.n+8);
    pad[0]=0x80; const dv=new DataView(pad.buffer);
    dv.setUint32(pad.length-8, Math.floor(bits/4294967296)); dv.setUint32(pad.length-4, bits>>>0);
    this.update(pad);
    const out=new Uint8Array(32), o=new DataView(out.buffer);
    this.h.forEach((v,i)=>o.setUint32(i*4,v)); return hex(out);
  }
}
async function sha256File(file){
  if(window.crypto?.subtle && file.size < 400*1024*1024){
    try { return hex(await crypto.subtle.digest("SHA-256", await file.arrayBuffer())); } catch(e){}
  }
  const s = new Sha256(), CH = 4*1024*1024;
  for(let p=0;p<file.size;p+=CH) s.update(new Uint8Array(await file.slice(p,p+CH).arrayBuffer()));
  return s.digest();
}
async function sha256Text(text){
  const data = new TextEncoder().encode(text);
  if(window.crypto?.subtle) return hex(await crypto.subtle.digest("SHA-256", data));
  const s = new Sha256(); s.update(data); return s.digest();
}

// Проверка по содержимому (EICAR)
async function sigCheck(file){
  if(file.size > 1024*1024) return null;
  const t = new TextDecoder("latin1").decode(await file.arrayBuffer());
  return t.includes(window.EICAR_SIGNATURE) ? {name:"EICAR-Test-File", labels:[]} : null;
}

// ---------- Вывод ----------
const esc = s => s.replace(/[&<>"]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
function card(name, hash, hit, isFolder){
  const el = document.createElement("div");
  el.className = "res" + (hit ? " bad" : "");
  let body;
  if(hit){
    body = `<div class="type">Type: Virus Detected</div>` +
      (hit.labels.length ? `<ul class="labels">${hit.labels.map(l=>`<li>${esc(l)}</li>`).join("")}</ul>` : "") +
      `<div class="hash">Detection: ${esc(hit.name)}</div>`;
  } else body = `<div class="type">Угроз не найдено</div>`;
  el.innerHTML = `<div class="name">${isFolder?"Папка":"Файл"}: ${esc(name)}</div>${body}<div class="hash">SHA-256: ${hash}</div>`;
  return el;
}

// ---------- Сканирование ----------
async function scan(files){
  results.innerHTML = ""; summary.textContent = "";
  files = [...files]; if(!files.length) return;
  const rel = f => f.webkitRelativePath || f.name;
  const root = files[0].webkitRelativePath ? files[0].webkitRelativePath.split("/")[0] : null;
  const rows = []; let bad = 0;
  for(let i=0;i<files.length;i++){
    progress.textContent = `Проверка ${i+1} из ${files.length}: ${rel(files[i])}`;
    const h = await sha256File(files[i]);
    rows.push([rel(files[i]), h]);
    const hit = DB.get(h) || await sigCheck(files[i]);
    if(hit) bad++;
    results.appendChild(card(rel(files[i]), h, hit, false));
  }
  // Хэш всей папки: SHA-256 от отсортированного списка "путь:хэш"
  if(root){
    const fh = await sha256Text(rows.slice().sort((a,b)=>a[0]<b[0]?-1:1).map(r=>r[0]+":"+r[1]).join("\n"));
    const hit = DB.get(fh); if(hit) bad++;
    results.prepend(card(root, fh, hit, true));
  }
  progress.textContent = "";
  summary.style.color = bad ? "var(--bad)" : "var(--ok)";
  summary.textContent = bad ? `Найдено угроз: ${bad}` : `Проверено: ${files.length}. Угроз не найдено.`;
}

// Перетаскивание (в том числе папок)
async function readEntry(entry, out){
  if(entry.isFile){ out.push(await new Promise(r => entry.file(f => { Object.defineProperty(f,"webkitRelativePath",{value:entry.fullPath.slice(1)}); r(f); }))); }
  else if(entry.isDirectory){
    const rd = entry.createReader();
    for(;;){ const batch = await new Promise(r => rd.readEntries(r)); if(!batch.length) break; for(const e of batch) await readEntry(e,out); }
  }
}
drop.addEventListener("dragover", e => { e.preventDefault(); drop.classList.add("over"); });
drop.addEventListener("dragleave", () => drop.classList.remove("over"));
drop.addEventListener("drop", async e => {
  e.preventDefault(); drop.classList.remove("over");
  const items = [...e.dataTransfer.items].map(i => i.webkitGetAsEntry && i.webkitGetAsEntry()).filter(Boolean);
  if(!items.length) return scan(e.dataTransfer.files);
  const out = []; let hasDir = items.some(i=>i.isDirectory);
  for(const it of items) await readEntry(it, out);
  if(!hasDir) out.forEach(f => Object.defineProperty(f,"webkitRelativePath",{value:""}));
  scan(out);
});
$("bFile").onclick = () => $("fFile").click();
$("bDir").onclick = () => $("fDir").click();
$("fFile").onchange = e => { scan(e.target.files); e.target.value = ""; };
$("fDir").onchange = e => { scan(e.target.files); e.target.value = ""; };
