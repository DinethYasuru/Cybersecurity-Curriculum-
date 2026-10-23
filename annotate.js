/* Presenter ink for the session decks: laser, pen, highlighter, underline, arrow, box, circle,
   spotlight, zoom, eraser, undo, clear. Press A (or the Draw button) to show the toolbar.
   Instructor only: it never starts for live-class students (?join=) or in the phone shell's outer page.
   Source of truth is this file; tools/inline-annotate.py copies it into every deck between the
   annotate:start / annotate:end markers so each deck stays a single self-contained HTML file. */
(function(){
if(window.__SHELL||window.__ANN)return;
try{if(new URLSearchParams(location.search).get('join'))return;}catch(e){}
window.__ANN=1;

const KEY='acm-ink';
let cfg={};try{cfg=JSON.parse(localStorage.getItem(KEY)||'{}')||{};}catch(e){}
const save=()=>{try{localStorage.setItem(KEY,JSON.stringify(cfg));}catch(e){}};
const COL={red:'#BF0A30',blue:'#002868',ink:'#15171e',yel:'#FFD60A'};
const HLC={red:'#f6bcc8',blue:'#c3d2f0',ink:'#d3d6de',yel:'#ffe14a'};
const SIZES=[3,5,9];
const TOOLS=[
  ['pointer','Pointer: click the slide','0','<path d="M6 3.5l12.5 7.2-5.6 1.6-2.6 5.4z"/>'],
  ['laser','Laser pointer','1','<circle cx="12" cy="12" r="3.3" fill="currentColor" stroke="none"/><path d="M12 2.8v2.6M12 18.6v2.6M2.8 12h2.6M18.6 12h2.6M5.5 5.5l1.8 1.8M16.7 16.7l1.8 1.8M5.5 18.5l1.8-1.8M16.7 7.3l1.8-1.8"/>'],
  ['pen','Pen','2','<path d="M4 20l1.2-4.4L15.8 5a2 2 0 012.9 0l.3.3a2 2 0 010 2.9L8.4 18.8z"/><path d="M14 7l3 3"/>'],
  ['hl','Highlighter','3','<path d="M4 21h16" stroke-width="3.2" opacity=".45"/><path d="M7.5 16.5l-2 2.5h4.5l1.2-1.3"/><path d="M8 15l1.8 1.8L19 8.2 15.8 5z"/>'],
  ['under','Underline','4','<path d="M7 4v6.5a5 5 0 0010 0V4"/><path d="M4.5 20h15"/>'],
  ['arrow','Arrow','5','<path d="M5 19L18.5 5.5"/><path d="M10 5h9v9"/>'],
  ['box','Box','6','<rect x="3.5" y="6" width="17" height="12" rx="2.6"/>'],
  ['ring','Circle','7','<ellipse cx="12" cy="12" rx="9" ry="7"/>'],
  ['spot','Spotlight (scroll to resize)','8','<rect x="3" y="3" width="18" height="18" rx="3.5" fill="currentColor" stroke="none" opacity=".2"/><circle cx="12" cy="12" r="5.2"/>'],
  ['zoom','Zoom: click to zoom, drag to move, scroll','9','<circle cx="10.5" cy="10.5" r="6.3"/><path d="M15.2 15.2L20 20M7.8 10.5h5.4M10.5 7.8v5.4"/>'],
  ['erase','Eraser','E','<path d="M8.5 20H20"/><path d="M4.6 14.4l8.8-8.8a2 2 0 012.8 0l3.2 3.2a2 2 0 010 2.8L13 18H8.2z"/><path d="M9.2 9.8l5 5"/>']
];
const NAMES={};TOOLS.forEach(t=>NAMES[t[0]]=t[1].split(':')[0].split(' (')[0]);
const PASS={pointer:1,laser:1,spot:1};
const SHAPE={under:1,arrow:1,box:1,ring:1};
const svg=d=>'<svg viewBox="0 0 24 24" aria-hidden="true">'+d+'</svg>';

const S={open:false,tool:TOOLS.some(t=>t[0]===cfg.tool)?cfg.tool:'laser',color:COL[cfg.color]?cfg.color:'red',hl:COL[cfg.hl]?cfg.hl:'yel',size:[0,1,2].includes(cfg.size)?cfg.size:1,
  keep:!!cfg.keep,fade:!!cfg.fade,strokes:[],undo:[],redo:[],cur:null,pid:null,mx:-1,my:-1,trail:[],spotR:cfg.spotR||150,
  z:{s:1,x:0,y:0},zt:null,pan:null,key:null,slides:new Map(),erased:null};

/* ---------- styles ---------- */
const css=document.createElement('style');css.id='annCss';
css.textContent=`
#annLayer{position:fixed;inset:0;z-index:2147482000;pointer-events:none;touch-action:none}
#annLayer.cap{pointer-events:auto}
#annLayer canvas{position:absolute;inset:0;width:100%;height:100%;display:block}
#annLayer .hl{mix-blend-mode:multiply}
html.ann-nocur,html.ann-nocur *{cursor:none!important}
#annBar{position:fixed;z-index:2147483000;left:50%;bottom:76px;transform:translateX(-50%);display:flex;width:max-content;box-sizing:border-box;flex-wrap:wrap;justify-content:center;align-items:center;gap:2px;
  max-width:calc(100vw - 24px);padding:6px;background:rgba(255,255,255,.94);-webkit-backdrop-filter:blur(14px);backdrop-filter:blur(14px);
  border:1px solid #e3e6ee;border-radius:16px;box-shadow:0 14px 38px rgba(0,40,104,.16),0 2px 6px rgba(21,23,30,.06);
  font-family:'DM Sans',system-ui,sans-serif;color:#15171e;user-select:none;-webkit-user-select:none;touch-action:none;
  opacity:0;translate:0 14px;scale:.97;pointer-events:none;transition:opacity .3s cubic-bezier(.22,1,.36,1),translate .45s cubic-bezier(.22,1,.36,1),scale .45s cubic-bezier(.22,1,.36,1)}
#annBar.on{opacity:1;translate:0 0;scale:1;pointer-events:auto}
body.idle #annBar.on:not(:hover){opacity:.55}
#annBar button{all:unset;box-sizing:border-box;width:40px;height:40px;border-radius:11px;display:grid;place-items:center;cursor:pointer;color:#15171e;position:relative;transition:background .2s,color .2s}
#annBar button:hover{background:#eef2f9}
#annBar button:focus-visible{outline:2px solid #002868;outline-offset:1px}
#annBar button svg{width:22px;height:22px;fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}
#annBar button.t.on{background:#002868;color:#fff}
#annBar button.tg.on{color:#002868;background:#e6ecf7}
#annBar button.tg.on::after{content:'';position:absolute;top:6px;right:6px;width:6px;height:6px;border-radius:50%;background:#BF0A30}
#annBar .sep{width:1px;height:26px;background:#e3e6ee;margin:0 4px}
#annBar .grip{cursor:grab;width:22px;color:#9aa1b2}
#annBar .grip:active{cursor:grabbing}
#annBar .grip svg{width:14px;height:22px;fill:currentColor;stroke:none}
#annBar .sw{width:30px}
#annBar .sw i{width:18px;height:18px;border-radius:50%;background:var(--c);box-shadow:inset 0 0 0 1px rgba(21,23,30,.14);transition:transform .25s cubic-bezier(.22,1,.36,1)}
#annBar .sw.on i{transform:scale(1.18);box-shadow:0 0 0 2px #fff,0 0 0 4px var(--c)}
#annBar .sz i{border-radius:50%;background:#15171e}
#annTip{position:fixed;z-index:2147483001;left:50%;bottom:136px;transform:translateX(-50%);padding:.45rem 1rem;border-radius:999px;background:#002868;color:#fff;
  font:600 15px/1.2 'DM Sans',system-ui,sans-serif;letter-spacing:.01em;pointer-events:none;opacity:0;transition:opacity .25s}
#annTip.on{opacity:1}
#annHelp{position:fixed;z-index:2147483001;left:50%;bottom:136px;transform:translateX(-50%);width:min(560px,calc(100vw - 24px));padding:18px 22px;border-radius:16px;
  background:#fff;border:1px solid #e3e6ee;box-shadow:0 18px 44px rgba(0,40,104,.18);font:15px/1.45 'DM Sans',system-ui,sans-serif;color:#15171e}
#annHelp[hidden]{display:none}
#annHelp h4{margin:0 0 10px;font:600 18px/1.2 Outfit,system-ui,sans-serif;color:#002868}
#annHelp dl{display:grid;grid-template-columns:auto 1fr auto 1fr;gap:6px 12px;margin:0}
#annHelp dt{font-weight:700;text-align:right;white-space:nowrap}
#annHelp dt kbd{font:600 13px/1 'DM Sans',system-ui,sans-serif;border:1px solid #e3e6ee;border-bottom-width:2px;border-radius:6px;padding:3px 7px;background:#f6f8fc}
#annHelp dd{margin:0;color:#3a3f4c}
@media (max-width:520px){#annHelp dl{grid-template-columns:auto 1fr}}
@media (prefers-reduced-motion:reduce){#annBar,#annBar *{transition:none!important}}
`;
document.head.appendChild(css);

/* ---------- layers ---------- */
const layer=document.createElement('div');layer.id='annLayer';layer.setAttribute('aria-hidden','true');
const cvH=document.createElement('canvas');cvH.className='hl';
const cvI=document.createElement('canvas');
layer.append(cvH,cvI);
const xH=cvH.getContext('2d'),xI=cvI.getContext('2d');
let dpr=1,W=0,H=0;
function size(){
  dpr=Math.min(2,window.devicePixelRatio||1);W=innerWidth;H=innerHeight;
  [cvH,cvI].forEach(c=>{c.width=Math.round(W*dpr);c.height=Math.round(H*dpr);});
  clampZoom();applyZoom();draw();
}

/* ---------- toolbar ---------- */
const bar=document.createElement('div');bar.id='annBar';bar.setAttribute('role','toolbar');bar.setAttribute('aria-label','Drawing tools');
const tip=document.createElement('div');tip.id='annTip';
const help=document.createElement('div');help.id='annHelp';help.hidden=true;
const K=(k,d)=>'<dt><kbd>'+k+'</kbd></dt><dd>'+d+'</dd>';
help.innerHTML='<h4>Drawing tools</h4><dl>'+
  K('A','Show / hide tools')+K('0','Pointer')+
  TOOLS.slice(1).map(t=>K(t[2],NAMES[t[0]])).join('')+
  K('R B K Y','Red, blue, black, yellow')+K('[ ]','Thinner / thicker')+
  K('Z','Undo')+K('Shift Z','Redo')+K('C','Clear slide')+K('Esc','Zoom out, then pointer')+
  K('Shift','Straight lines, perfect shapes')+K('?','This help')+'</dl>';
let h='<button class="grip" type="button" title="Drag to move" aria-label="Move toolbar">'+'<svg viewBox="0 0 10 22"><circle cx="3" cy="5" r="1.4"/><circle cx="7" cy="5" r="1.4"/><circle cx="3" cy="11" r="1.4"/><circle cx="7" cy="11" r="1.4"/><circle cx="3" cy="17" r="1.4"/><circle cx="7" cy="17" r="1.4"/></svg></button>';
TOOLS.forEach((t,k)=>{h+='<button class="t" type="button" data-t="'+t[0]+'" title="'+t[1]+' ('+t[2]+')" aria-label="'+t[1]+'">'+svg(t[3])+'</button>';if(k===1)h+='<span class="sep"></span>';});
h+='<span class="sep"></span>';
[['red','Red (R)'],['blue','Blue (B)'],['ink','Black (K)'],['yel','Yellow (Y)']].forEach(c=>{h+='<button class="sw" type="button" data-c="'+c[0]+'" style="--c:'+COL[c[0]]+'" title="'+c[1]+'" aria-label="'+c[1]+'"><i></i></button>';});
h+='<button class="sz" type="button" title="Line size ([ and ])" aria-label="Line size"><i></i></button>';
h+='<span class="sep"></span>';
h+='<button type="button" data-a="undo" title="Undo (Z)" aria-label="Undo">'+svg('<path d="M9 14L4 9l5-5"/><path d="M4 9h10.5a5.5 5.5 0 010 11H11"/>')+'</button>';
h+='<button type="button" data-a="clear" title="Clear this slide (C)" aria-label="Clear">'+svg('<path d="M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3"/>')+'</button>';
h+='<button class="tg" type="button" data-a="keep" title="Keep drawings on each slide when you move on" aria-label="Keep drawings per slide">'+svg('<path d="M12 3.5l8.5 4.5-8.5 4.5L3.5 8z"/><path d="M3.5 12.2l8.5 4.5 8.5-4.5"/><path d="M3.5 16.2l8.5 4.5 8.5-4.5"/>')+'</button>';
h+='<button class="tg" type="button" data-a="fade" title="Vanishing ink: drawings fade after 2 seconds" aria-label="Vanishing ink">'+svg('<path d="M3.5 17c3-6.5 5.5-6.5 7.5-2.2s4.5 4 8-3.3"/><path d="M17 4.2v3M15.5 5.7h3M20.6 9.4v1.8M19.7 10.3h1.8"/>')+'</button>';
h+='<button type="button" data-a="help" title="Shortcuts (?)" aria-label="Shortcuts">'+svg('<circle cx="12" cy="12" r="8.5"/><path d="M9.6 9.4a2.5 2.5 0 014.8.9c0 1.7-2.4 2.2-2.4 3.7"/><path d="M12 17.2v.01" stroke-width="2.4"/>')+'</button>';
h+='<button type="button" data-a="close" title="Hide tools (A)" aria-label="Hide tools">'+svg('<path d="M6.5 6.5l11 11M17.5 6.5l-11 11"/>')+'</button>';
bar.innerHTML=h;

function refreshBar(){
  bar.querySelectorAll('.t').forEach(b=>{const on=b.dataset.t===S.tool;b.classList.toggle('on',on);b.setAttribute('aria-pressed',on);});
  const cc=S.tool==='hl'?S.hl:S.color;
  bar.querySelectorAll('.sw').forEach(b=>{const on=b.dataset.c===cc;b.classList.toggle('on',on);b.setAttribute('aria-pressed',on);});
  const d=[8,12,17][S.size],i=bar.querySelector('.sz i');i.style.width=i.style.height=d+'px';
  bar.querySelector('[data-a=keep]').classList.toggle('on',S.keep);
  bar.querySelector('[data-a=fade]').classList.toggle('on',S.fade);
}
let tipT;
function say(t){tip.textContent=t;tip.classList.add('on');clearTimeout(tipT);tipT=setTimeout(()=>tip.classList.remove('on'),1100);place();}
function place(){
  if(!S.open)return;
  const r=bar.getBoundingClientRect(),above=r.top>150;
  [tip,help].forEach(el=>{el.style.left=(r.left+r.width/2)+'px';
    if(above){el.style.top='';el.style.bottom=(innerHeight-r.top+10)+'px';}else{el.style.bottom='';el.style.top=(r.bottom+10)+'px';}});
}
function placeBar(){
  const p=cfg.pos;
  if(!p){bar.style.left='';bar.style.top='';bar.style.bottom='';bar.style.transform='';return;}
  const r=bar.getBoundingClientRect();
  const x=Math.max(8,Math.min(innerWidth-r.width-8,p[0]*innerWidth)),y=Math.max(8,Math.min(innerHeight-r.height-8,p[1]*innerHeight));
  bar.style.transform='none';bar.style.bottom='auto';bar.style.left=x+'px';bar.style.top=y+'px';
}

/* ---------- state changes ---------- */
function setTool(t,quiet){
  if(S.cur)endStroke();
  S.tool=t;if(t!=='pointer'){cfg.tool=t;save();}
  layer.classList.toggle('cap',S.open&&!PASS[t]);
  document.documentElement.classList.toggle('ann-nocur',S.open&&(t==='laser'||t==='erase'));
  cursor();refreshBar();if(!quiet)say(NAMES[t]);draw();
}
function cursor(){
  const t=S.tool;
  layer.style.cursor=t==='zoom'?(S.pan&&S.pan.moved?'grabbing':S.z.s>1?'zoom-out':'zoom-in'):SHAPE[t]||t==='pen'||t==='hl'?'crosshair':'';
}
function setOpen(o){
  S.open=o;bar.classList.toggle('on',o);help.hidden=true;
  if(drawBtn)drawBtn.classList.toggle('ann-on',o);
  if(o){placeBar();setTool(S.tool==='pointer'?(cfg.tool||'laser'):S.tool);}
  else{if(S.cur)endStroke();layer.classList.remove('cap');document.documentElement.classList.remove('ann-nocur');S.trail=[];zoomTo(1,0,0,true);draw();}
}
function setColor(c){if(S.tool==='hl'){S.hl=c;cfg.hl=c;}else{S.color=c;cfg.color=c;}save();say({red:'Red',blue:'Blue',ink:'Black',yel:'Yellow'}[c]);if(PASS[S.tool]&&S.tool!=='laser')setTool('pen',true);else refreshBar();}
function setSize(n){S.size=Math.max(0,Math.min(2,n));cfg.size=S.size;save();refreshBar();say(['Thin','Medium','Thick'][S.size]);}
function toggle(k){S[k]=!S[k];cfg[k]=S[k];save();refreshBar();say(k==='keep'?(S.keep?'Drawings stay on each slide':'Drawings clear on slide change'):(S.fade?'Vanishing ink on':'Vanishing ink off'));if(k==='fade'&&S.fade){const n=performance.now();S.strokes.forEach(s=>s.end=s.end||n);draw();}}
function act(a,s){S.undo.push(a);if(S.undo.length>300)S.undo.shift();S.redo=[];}
function undo(){const a=S.undo.pop();if(!a)return say('Nothing to undo');
  if(a.add)S.strokes=S.strokes.filter(s=>s!==a.add);else S.strokes.push(...a.del);S.redo.push(a);draw();say('Undo');}
function redo(){const a=S.redo.pop();if(!a)return;
  if(a.add)S.strokes.push(a.add);else S.strokes=S.strokes.filter(s=>!a.del.includes(s));S.undo.push(a);draw();say('Redo');}
function clear(){if(!S.strokes.length)return;act({del:S.strokes.slice()});S.strokes=[];draw();say('Cleared');}

/* ---------- zoom (transforms the deck, ink follows) ---------- */
const app=()=>document.getElementById('app')||document.body.firstElementChild;
function clampZoom(){const z=S.z;z.s=Math.max(1,Math.min(5,z.s));z.x=Math.min(0,Math.max(W-W*z.s,z.x));z.y=Math.min(0,Math.max(H-H*z.s,z.y));}
function applyZoom(){const a=app();if(!a)return;const z=S.z;
  if(z.s===1&&!S.zt){a.style.transform='';a.style.transformOrigin='';}
  else{a.style.transformOrigin='0 0';a.style.transform='translate('+z.x.toFixed(2)+'px,'+z.y.toFixed(2)+'px) scale('+z.s.toFixed(4)+')';}}
function zoomTo(s,px,py,now){
  const z=S.z,bx=(px-z.x)/z.s,by=(py-z.y)/z.s,to={s:Math.max(1,Math.min(5,s))};
  to.x=px-bx*to.s;to.y=py-by*to.s;
  if(to.s===1){to.x=0;to.y=0;}
  const tmp={s:z.s,x:z.x,y:z.y};S.z=to;clampZoom();const end=S.z;S.z=tmp;
  if(now||matchMedia('(prefers-reduced-motion: reduce)').matches){S.z=end;S.zt=null;applyZoom();draw();cursor();return;}
  S.zt={from:tmp,to:end,t0:performance.now()};need();
}
function stepZoom(n){const t=S.zt;if(!t)return false;let k=Math.min(1,(n-t.t0)/420);const e=1-Math.pow(1-k,3);
  S.z={s:t.from.s+(t.to.s-t.from.s)*e,x:t.from.x+(t.to.x-t.from.x)*e,y:t.from.y+(t.to.y-t.from.y)*e};
  if(k>=1){S.z=t.to;S.zt=null;cursor();}applyZoom();return !!S.zt;}
const toBase=(x,y)=>[(x-S.z.x)/S.z.s,(y-S.z.y)/S.z.s];

/* ---------- drawing ---------- */
function width(s){return SIZES[s.sz]*(s.t==='hl'?4.6:s.t==='under'?1.5:1);}
function shapePts(s){
  const [a,b]=s.p;if(!b)return s.p;
  if(s.t==='under'||s.t==='arrow')return [a,b];
  if(s.t==='box')return [a,[b[0],a[1]],b,[a[0],b[1]],a];
  const cx=(a[0]+b[0])/2,cy=(a[1]+b[1])/2,rx=Math.abs(b[0]-a[0])/2,ry=Math.abs(b[1]-a[1])/2,o=[];
  for(let k=0;k<=36;k++){const t=k/36*Math.PI*2;o.push([cx+rx*Math.cos(t),cy+ry*Math.sin(t)]);}return o;
}
function strokeOne(s,n){
  let al=1;
  if(S.fade&&s.end){al=1-(n-s.end-1800)/700;if(al<=0)return false;al=Math.min(1,al);}
  const x=s.t==='hl'?xH:xI,w=width(s),p=s.p;
  x.save();x.globalAlpha=al;x.lineCap='round';x.lineJoin='round';x.lineWidth=w;
  x.strokeStyle=x.fillStyle=s.t==='hl'?HLC[s.c]:COL[s.c];
  if(s.t==='pen'||s.t==='hl'){
    if(p.length<2){x.beginPath();x.arc(p[0][0],p[0][1],w/2,0,Math.PI*2);x.fill();}
    else if(s.t==='pen'&&s.pr){
      for(let i=1;i<p.length;i++){const a=i>1?mid(p[i-2],p[i-1]):p[0],b=mid(p[i-1],p[i]);
        x.lineWidth=w*(.35+1.3*p[i][2]);x.beginPath();x.moveTo(a[0],a[1]);x.quadraticCurveTo(p[i-1][0],p[i-1][1],b[0],b[1]);x.stroke();}
    }else{
      x.beginPath();x.moveTo(p[0][0],p[0][1]);
      for(let i=1;i<p.length-1;i++){const m=mid(p[i],p[i+1]);x.quadraticCurveTo(p[i][0],p[i][1],m[0],m[1]);}
      const l=p[p.length-1];x.lineTo(l[0],l[1]);x.stroke();
    }
  }else if(p[1]){
    const [a,b]=p;x.beginPath();
    if(s.t==='under'){x.moveTo(a[0],a[1]);x.lineTo(b[0],b[1]);x.stroke();}
    else if(s.t==='arrow'){
      const ang=Math.atan2(b[1]-a[1],b[0]-a[0]),len=Math.hypot(b[0]-a[0],b[1]-a[1]),hl=Math.min(len*.6,Math.max(16,w*4.2)),hw=.48;
      x.moveTo(a[0],a[1]);x.lineTo(b[0]-Math.cos(ang)*hl*.7,b[1]-Math.sin(ang)*hl*.7);x.stroke();
      x.beginPath();x.moveTo(b[0],b[1]);x.lineTo(b[0]-hl*Math.cos(ang-hw),b[1]-hl*Math.sin(ang-hw));x.lineTo(b[0]-hl*Math.cos(ang+hw),b[1]-hl*Math.sin(ang+hw));x.closePath();x.fill();x.lineWidth=Math.max(2,w*.6);x.stroke();
    }else if(s.t==='box'){const l=Math.min(a[0],b[0]),t=Math.min(a[1],b[1]),bw=Math.abs(b[0]-a[0]),bh=Math.abs(b[1]-a[1]),r=Math.min(14,bw/2,bh/2);
      if(x.roundRect)x.roundRect(l,t,bw,bh,r);else x.rect(l,t,bw,bh);x.stroke();}
    else{x.ellipse((a[0]+b[0])/2,(a[1]+b[1])/2,Math.abs(b[0]-a[0])/2,Math.abs(b[1]-a[1])/2,0,0,Math.PI*2);x.stroke();}
  }
  x.restore();return true;
}
const mid=(a,b)=>[(a[0]+b[0])/2,(a[1]+b[1])/2];
let raf=0;
function need(){if(!raf)raf=requestAnimationFrame(frame);}
function frame(n){raf=0;let again=stepZoom(n);again=render(n)||again;if(again)need();}
function draw(){need();}
function render(n){
  let again=false;
  [xH,xI].forEach(x=>{x.setTransform(1,0,0,1,0,0);x.clearRect(0,0,x.canvas.width,x.canvas.height);
    x.setTransform(dpr*S.z.s,0,0,dpr*S.z.s,dpr*S.z.x,dpr*S.z.y);});
  if(S.fade){const keep=[];S.strokes.forEach(s=>{if(strokeOne(s,n))keep.push(s);});if(keep.length!==S.strokes.length)S.strokes=keep;again=S.strokes.length>0;}
  else S.strokes.forEach(s=>strokeOne(s,n));
  if(S.cur)strokeOne(S.cur,n);
  xI.setTransform(dpr,0,0,dpr,0,0);
  if(S.open&&S.tool==='spot'&&S.mx>=0){
    const r=S.spotR,g=xI.createRadialGradient(S.mx,S.my,r*.9,S.mx,S.my,r+26);
    g.addColorStop(0,'rgba(6,12,32,0)');g.addColorStop(1,'rgba(6,12,32,.66)');xI.fillStyle=g;xI.fillRect(0,0,W,H);
    xI.lineWidth=1.5;xI.strokeStyle='rgba(255,255,255,.55)';xI.beginPath();xI.arc(S.mx,S.my,r+2,0,Math.PI*2);xI.stroke();
  }
  if(S.open&&S.tool==='erase'&&S.mx>=0){const r=eraseR()*S.z.s;xI.lineWidth=1.5;xI.strokeStyle='#002868';xI.fillStyle='rgba(255,255,255,.55)';xI.beginPath();xI.arc(S.mx,S.my,r,0,Math.PI*2);xI.fill();xI.stroke();}
  if(S.open&&S.tool==='laser'){
    const life=320;S.trail=S.trail.filter(p=>n-p[2]<life);
    const c=S.color==='yel'?'255,214,10':S.color==='blue'?'40,96,210':S.color==='ink'?'21,23,30':'232,20,60';
    for(let i=1;i<S.trail.length;i++){const a=S.trail[i-1],b=S.trail[i],k=1-(n-b[2])/life;
      xI.strokeStyle='rgba('+c+','+(k*.55).toFixed(3)+')';xI.lineCap='round';xI.lineWidth=2+k*9;xI.beginPath();xI.moveTo(a[0],a[1]);xI.lineTo(b[0],b[1]);xI.stroke();}
    if(S.mx>=0){const g=xI.createRadialGradient(S.mx,S.my,0,S.mx,S.my,26);
      g.addColorStop(0,'rgba(255,255,255,1)');g.addColorStop(.16,'rgba('+c+',1)');g.addColorStop(.42,'rgba('+c+',.38)');g.addColorStop(1,'rgba('+c+',0)');
      xI.fillStyle=g;xI.beginPath();xI.arc(S.mx,S.my,26,0,Math.PI*2);xI.fill();}
    if(S.trail.length)again=true;
  }
  return again;
}

/* ---------- eraser ---------- */
function eraseR(){return 10+SIZES[S.size]*2;}
function dseg(p,a,b){const dx=b[0]-a[0],dy=b[1]-a[1],l=dx*dx+dy*dy;let t=l?((p[0]-a[0])*dx+(p[1]-a[1])*dy)/l:0;t=Math.max(0,Math.min(1,t));return Math.hypot(p[0]-a[0]-t*dx,p[1]-a[1]-t*dy);}
function eraseAt(x,y){
  const p=toBase(x,y),r=eraseR();
  const hit=S.strokes.filter(s=>{const q=SHAPE[s.t]?shapePts(s):s.p,lim=r+width(s)/2;
    if(q.length===1)return Math.hypot(p[0]-q[0][0],p[1]-q[0][1])<lim;
    for(let i=1;i<q.length;i++)if(dseg(p,q[i-1],q[i])<lim)return true;return false;});
  if(hit.length){S.strokes=S.strokes.filter(s=>!hit.includes(s));S.erased.push(...hit);}
}

/* ---------- pointer input ---------- */
function pts(e){const l=e.getCoalescedEvents?e.getCoalescedEvents():[];return l.length?l:[e];}
function pr(e){return e.pointerType==='pen'&&e.pressure>0?e.pressure:.5;}
layer.addEventListener('pointerdown',e=>{
  if(!S.open||PASS[S.tool]||S.pid!==null)return;
  if(e.pointerType==='mouse'&&e.button!==0)return;
  e.preventDefault();S.pid=e.pointerId;try{layer.setPointerCapture(e.pointerId);}catch(x){}
  S.mx=e.clientX;S.my=e.clientY;const t=S.tool,b=toBase(e.clientX,e.clientY);
  if(t==='zoom'){S.pan={x:e.clientX,y:e.clientY,zx:S.z.x,zy:S.z.y,moved:false};return;}
  if(t==='erase'){S.erased=[];eraseAt(e.clientX,e.clientY);draw();return;}
  S.cur={t,c:t==='hl'?S.hl:S.color,sz:S.size,p:[[b[0],b[1],pr(e)]],pr:e.pointerType==='pen'};
  if(SHAPE[t])S.cur.p.push([b[0],b[1]]);
  draw();
});
layer.addEventListener('pointermove',e=>{
  S.mx=e.clientX;S.my=e.clientY;
  if(e.pointerId!==S.pid){if(S.tool==='erase')draw();return;}
  const t=S.tool;
  if(t==='zoom'&&S.pan){const P=S.pan;if(Math.hypot(e.clientX-P.x,e.clientY-P.y)>6)P.moved=true;
    if(P.moved&&S.z.s>1){S.z.x=P.zx+e.clientX-P.x;S.z.y=P.zy+e.clientY-P.y;clampZoom();applyZoom();draw();}cursor();return;}
  if(t==='erase'){eraseAt(e.clientX,e.clientY);draw();return;}
  const c=S.cur;if(!c)return;
  if(SHAPE[t]){let b=toBase(e.clientX,e.clientY);const a=c.p[0];
    if(t==='under')b=[b[0],a[1]];
    else if(e.shiftKey&&t==='arrow'){const ang=Math.round(Math.atan2(b[1]-a[1],b[0]-a[0])/(Math.PI/4))*(Math.PI/4),l=Math.hypot(b[0]-a[0],b[1]-a[1]);b=[a[0]+l*Math.cos(ang),a[1]+l*Math.sin(ang)];}
    else if(e.shiftKey){const d=Math.max(Math.abs(b[0]-a[0]),Math.abs(b[1]-a[1]));b=[a[0]+d*Math.sign(b[0]-a[0]||1),a[1]+d*Math.sign(b[1]-a[1]||1)];}
    c.p[1]=b;
  }else pts(e).forEach(q=>{const b=toBase(q.clientX,q.clientY),l=c.p[c.p.length-1];
    if(Math.hypot(b[0]-l[0],b[1]-l[1])*S.z.s>=1.5)c.p.push([b[0],b[1],pr(q)]);});
  if(e.shiftKey&&t==='hl'&&c.p.length>1){const a=c.p[0],l=c.p[c.p.length-1];c.p=[a,[l[0],a[1],l[2]]];}
  draw();
});
function endStroke(e){
  const t=S.tool;
  if(t==='zoom'&&S.pan){const P=S.pan;S.pan=null;
    if(!P.moved&&e)zoomTo(S.z.s>1?1:2.2,e.clientX,e.clientY);cursor();}
  else if(t==='erase'&&S.erased){if(S.erased.length)act({del:S.erased});S.erased=null;}
  else if(S.cur){const c=S.cur;S.cur=null;
    if(c.t==='hl'&&c.p.length>2){const a=c.p[0],l=c.p[c.p.length-1],dx=l[0]-a[0],maxDy=Math.max(...c.p.map(q=>Math.abs(q[1]-a[1])));
      if(Math.abs(dx)>40&&maxDy<16){const y=c.p.reduce((s,q)=>s+q[1],0)/c.p.length;c.p=[[a[0],y,.5],[l[0],y,.5]];}}
    const ok=SHAPE[c.t]?Math.hypot(c.p[1][0]-c.p[0][0],c.p[1][1]-c.p[0][1])>4:true;
    if(ok){if(S.fade)c.end=performance.now();S.strokes.push(c);act({add:c});}
  }
  if(S.pid!==null){try{layer.releasePointerCapture(S.pid);}catch(x){}}
  S.pid=null;draw();
}
layer.addEventListener('pointerup',e=>{if(e.pointerId===S.pid)endStroke(e);});
layer.addEventListener('pointercancel',e=>{if(e.pointerId===S.pid){S.pan=null;endStroke();}});
layer.addEventListener('pointerleave',()=>{if(S.tool==='erase'&&S.pid===null){S.mx=-1;draw();}});
/* laser and spotlight follow the pointer but let clicks reach the slide */
addEventListener('pointermove',e=>{
  if(!S.open||!PASS[S.tool]||S.tool==='pointer')return;
  S.mx=e.clientX;S.my=e.clientY;
  if(S.tool==='laser')pts(e).forEach(q=>S.trail.push([q.clientX,q.clientY,performance.now()]));
  draw();
},{capture:true,passive:true});
addEventListener('pointerup',e=>{if(S.open&&PASS[S.tool]&&e.pointerType!=='mouse'){S.mx=-1;draw();}},true);
document.documentElement.addEventListener('mouseleave',()=>{if(S.open&&PASS[S.tool]){S.mx=-1;S.trail=[];draw();}});
/* with laser or spotlight on a touch screen, a drag points instead of swiping slides */
['touchstart','touchmove','touchend'].forEach(ev=>addEventListener(ev,e=>{
  if(S.open&&(S.tool==='laser'||S.tool==='spot')&&!bar.contains(e.target))e.stopPropagation();
},{capture:true,passive:true}));
addEventListener('wheel',e=>{
  if(!S.open||bar.contains(e.target))return;
  if(S.tool==='spot'){e.preventDefault();S.spotR=Math.max(60,Math.min(420,S.spotR*(e.deltaY>0?.9:1.1)));cfg.spotR=Math.round(S.spotR);save();draw();}
  else if(S.tool==='zoom'){e.preventDefault();S.zt=null;zoomTo(S.z.s*(e.deltaY>0?.85:1.18),e.clientX,e.clientY,true);}
},{capture:true,passive:false});

/* toolbar clicks and dragging */
bar.addEventListener('click',e=>{
  const b=e.target.closest('button');if(!b)return;
  if(b.dataset.t)setTool(b.dataset.t);
  else if(b.dataset.c)setColor(b.dataset.c);
  else if(b.classList.contains('sz'))setSize((S.size+1)%3);
  else if(b.dataset.a==='undo')undo();
  else if(b.dataset.a==='clear')clear();
  else if(b.dataset.a==='keep')toggle('keep');
  else if(b.dataset.a==='fade')toggle('fade');
  else if(b.dataset.a==='help'){help.hidden=!help.hidden;place();}
  else if(b.dataset.a==='close')setOpen(false);
  if(e.detail)b.blur();
});
(function(){
  const g=bar.querySelector('.grip');let d=null;
  g.addEventListener('pointerdown',e=>{e.preventDefault();const r=bar.getBoundingClientRect();d={dx:e.clientX-r.left,dy:e.clientY-r.top};g.setPointerCapture(e.pointerId);});
  g.addEventListener('pointermove',e=>{if(!d)return;cfg.pos=[(e.clientX-d.dx)/innerWidth,(e.clientY-d.dy)/innerHeight];placeBar();place();});
  g.addEventListener('pointerup',()=>{if(d){d=null;save();}});
  g.addEventListener('dblclick',()=>{delete cfg.pos;save();placeBar();place();});
})();

/* ---------- keys (capture phase, so the deck never sees the ones we use) ---------- */
const DECK_PANELS={m:1,n:1,l:1};
addEventListener('keydown',e=>{
  const t=e.target,tn=t&&t.tagName;
  if(tn==='INPUT'||tn==='TEXTAREA'||tn==='SELECT'||(t&&t.isContentEditable))return;
  const k=e.key,lk=k.length===1?k.toLowerCase():k,mod=e.ctrlKey||e.metaKey;
  const eat=()=>{e.preventDefault();e.stopImmediatePropagation();};
  if(!mod&&!e.altKey&&lk==='a'){eat();setOpen(!S.open);return;}
  if(!S.open)return;
  if(mod&&(lk==='z'||lk==='y')){eat();(lk==='y'||e.shiftKey)?redo():undo();return;}
  if(mod||e.altKey)return;
  const tool=TOOLS.find(x=>x[2].toLowerCase()===lk);
  if(tool){eat();setTool(tool[0]);return;}
  if(lk==='z'){eat();e.shiftKey?redo():undo();}
  else if(lk==='c'){eat();clear();}
  else if(lk==='r'||lk==='b'||lk==='k'||lk==='y'){eat();setColor({r:'red',b:'blue',k:'ink',y:'yel'}[lk]);}
  else if(k==='['){eat();setSize(S.size-1);}
  else if(k===']'){eat();setSize(S.size+1);}
  else if(k==='?'){eat();help.hidden=!help.hidden;place();}
  else if(k==='Escape'){
    if(!help.hidden){eat();help.hidden=true;}
    else if(S.cur){eat();S.cur=null;S.pid=null;draw();}
    else if(S.z.s>1){eat();zoomTo(1,innerWidth/2,innerHeight/2);}
    else if(S.tool!=='pointer'){eat();setTool('pointer');}
  }
  else if(DECK_PANELS[lk]&&!PASS[S.tool])setTool('pointer',true);
},true);

/* ---------- slide changes: clear, or keep per slide ---------- */
function slideKey(){if(location.hash)return location.hash;const a=document.querySelector('.slide.active');return a?'#'+(a.dataset.id||''):'';}
function watch(){
  const k=slideKey();if(k===S.key)return;
  if(S.cur){S.cur=null;S.pid=null;}
  if(S.key!==null&&S.keep&&(S.strokes.length||S.undo.length))S.slides.set(S.key,{strokes:S.strokes,undo:S.undo,redo:S.redo});
  const o=S.keep&&S.slides.get(k);
  S.strokes=o?o.strokes:[];S.undo=o?o.undo:[];S.redo=o?o.redo:[];
  S.key=k;S.trail=[];
  if(S.z.s>1||S.zt){S.zt=null;S.z={s:1,x:0,y:0};applyZoom();}
  draw();
}
addEventListener('hashchange',watch);

/* the deck's own bar gets a Draw button, like Live in 2b */
let drawBtn=null;
function addButton(){
  const fsb=document.getElementById('fsBtn');if(!fsb||document.getElementById('annBtn'))return;
  drawBtn=document.createElement('button');drawBtn.className='nb opt';drawBtn.id='annBtn';drawBtn.type='button';
  drawBtn.title='Laser, pen and highlighter (A)';drawBtn.textContent='Draw';
  drawBtn.onclick=e=>{setOpen(!S.open);if(e.detail)drawBtn.blur();};
  fsb.before(drawBtn);
}

function boot(){
  document.body.append(layer,bar,tip,help);
  addButton();refreshBar();size();watch();
  setInterval(watch,150);
  addEventListener('resize',()=>{size();if(S.open){placeBar();place();}});
}
if(document.body)boot();else document.addEventListener('DOMContentLoaded',boot);
})();
