// Attendance server checks: run against `wrangler dev` (see .github/workflows/attendance-tests.yml).
// A fresh local database with the main password pass12345; SETUP_KEY comes from .dev.vars or the environment.
const fs = require('fs');
const W = process.env.ATT_URL || 'http://localhost:8787/';
const KEY = process.env.SETUP_KEY || fs.readFileSync(__dirname + '/../.dev.vars', 'utf8').match(/SETUP_KEY=(.*)/)[1].trim();
const call = async b => (await fetch(W, { method: 'POST', body: JSON.stringify(b) })).json();
// the same, from another internet address (wrangler dev takes the client's cf-connecting-ip; Cloudflare itself sets it)
const callFrom = async (ip, b) => (await fetch(W, { method: 'POST', headers: { 'cf-connecting-ip': ip }, body: JSON.stringify(b) })).json();
let f = 0; const ok = (n, v, x) => { console.log(v ? 'PASS' : 'FAIL', n, v ? '' : JSON.stringify(x).slice(0, 300)); if (!v) f++; };
const section = n => console.log('\n## ' + n);
(async () => {
 await call({ action: 'maint', key: KEY, op: 'setPassword', password: 'pass12345' });
 section('Branch, open classes, coordinator download, sign out everywhere, Danger zone wait');
const A=(await call({action:'login',password:'pass12345'})).token;ok('admin login',!!A);
 let g=await (await fetch(W)).json();ok('branch default',g.branch&&g.branch.name==='American Corner Matara',g.branch);
 let r=await call({action:'branchSave',token:A,name:'American Corner Galle',logo:'data:text/html;base64,AAAA'});ok('bad logo refused',!r.ok,r);
 r=await call({action:'branchSave',token:A,name:'American Corner Galle',logo:'data:image/png;base64,iVBORw0KGgo='});ok('branch saved',r.ok&&r.branch.name==='American Corner Galle',r);
 g=await (await fetch(W)).json();ok('GET shows branch',g.branch.name==='American Corner Galle'&&g.branch.logo.startsWith('data:image/png'),g.branch);
 r=await call({action:'status'});ok('student status shows branch',r.branch&&r.branch.name==='American Corner Galle',r);
 r=await call({action:'data',token:A,k:'cyber'});ok('data shows branch',r.corner.branch.name==='American Corner Galle',r.corner);
 r=await call({action:'staffSave',token:A,kind:'coord',name:'Coord Person',phone:'0716666666',password:'coord1234'});
 let Co=(await call({action:'login',phone:'0716666666',password:'coord1234'})).token;await call({action:'myAccount',token:Co,name:'Coord Person',password:'coordpass1',oldPassword:'coord1234'});Co=(await call({action:'login',phone:'0716666666',password:'coordpass1'})).token;
 r=await call({action:'branchSave',token:Co,name:'Hacked Branch'});ok('coordinator cannot change branch',!r.ok,r);
 // classes and open hours
 const ids=[];for(let i=0;i<30;i++){const x=await call({action:'classSave',token:A,name:'Class '+String.fromCharCode(65+i%26)+(i>25?i:'')});if(x.ok)ids.push(x.class.id)}
 ok('30 classes made',ids.length===30,ids.length);
 // close every class now (extra 0 + a window that never matches), open one with an extra window
 const cyber=await call({action:'data',token:A,k:'cyber'});const st=cyber.settings;
 const closed=Object.assign({},st,{days:[(new Date(Date.now()+330*60000).getUTCDay()+3)%7],start:'09:00',end:'10:00'});
 for(const k of ['cyber',...ids]){const x=await call({action:'settings',token:A,k,settings:closed});if(!x.ok){ok('settings '+k,false,x);break}}
 r=await call({action:'status'});ok('none open',r.classes.every(c=>!c.open),r.classes.filter(c=>c.open));
 r=await call({action:'extra',token:A,k:ids[7],minutes:30});ok('extra window',r.ok,r);
 r=await call({action:'status'});ok('only that class open, picked',r.k===ids[7]&&r.classes.filter(c=>c.open).length===1,{k:r.k,open:r.classes.filter(c=>c.open)});
 r=await call({action:'extra',token:A,k:ids[12],minutes:30});
 r=await call({action:'status'});ok('two open: pick',r.pick===true&&r.classes.filter(c=>c.open).length===2,{pick:r.pick});
 // anonymous check-in (students sign in to the app is on by default; checked in its own section)
 await call({action:'stuLoginSet',token:A,on:false});
 // the student's number finds their class: no list
 const free=Object.assign({},closed,{requireCode:false,selfRegister:true});
 for(const k of [ids[7],ids[12]])await call({action:'settings',token:A,k,settings:free});
 r=await call({action:'register',k:ids[12],phone:'0751112222',name:'Nimal Perera',device:'devnimal01'});ok('student joins one class',r.ok,r);
 r=await call({action:'lookup',phone:'0751112222',device:'devnimal01'});ok('number finds the class',r.ok&&r.k===ids[12]&&r.found,{k:r.k,reason:r.reason});
 r=await call({action:'register',k:ids[7],phone:'0751112222',name:'Nimal Perera',device:'devnimal01'});ok('joins a second class',r.ok,r);
 r=await call({action:'lookup',phone:'0751112222',device:'devnimal01'});ok('two of theirs open: short list',r.reason==='pick'&&r.mine&&r.classes.length===2,r);
 r=await call({action:'lookup',phone:'0759998888',device:'devother02'});ok('new number: full list',r.reason==='pick'&&!r.mine,r);
 for(const k of [ids[7],ids[12]])await call({action:'settings',token:A,k,settings:closed});
 r=await call({action:'extra',token:A,k:ids[12],minutes:0});r=await call({action:'extra',token:A,k:ids[7],minutes:0});
 r=await call({action:'status'});ok('closed again',r.classes.every(c=>!c.open)&&!r.pick,r.classes.filter(c=>c.open));
 // a window that includes now (any day)
 const now=new Date(Date.now()+330*60000),hh=now.getUTCHours();const p2=n=>String(n).padStart(2,'0');
 r=await call({action:'settings',token:A,k:ids[3],settings:Object.assign({},st,{days:[0,1,2,3,4,5,6],start:p2(hh)+':00',end:p2(Math.min(hh+1,23))+':59'})});ok('open window set',r.ok,r);
 r=await call({action:'status'});ok('window class open',r.k===ids[3],{k:r.k});
 // coordinator download
 r=await call({action:'export',token:Co,k:'cyber'});ok('coordinator can download',r.ok&&r.kind==='attendance-backup',r);
 r=await call({action:'settings',token:Co,k:'cyber',settings:st});ok('coordinator still cannot change',!r.ok,r);
 // setup sign out everywhere
 r=await call({action:'maint',key:KEY,op:'reset'});ok('setup reset',r.ok,r);
 r=await call({action:'data',token:Co,k:'cyber'});ok('coordinator signed out',!r.ok&&r.reason==='auth',r);
 const A2=(await call({action:'login',password:'pass12345'})).token;
 // danger: waiting, not locked
 r=await call({action:'danger',token:A2,password:'bad',op:'open'});ok('wrong',r.reason==='password',r);
 r=await call({action:'danger',token:A2,password:'pass12345',op:'open'});ok('must wait 2s',r.reason==='wait',r);
 await new Promise(z=>setTimeout(z,2200));
 r=await call({action:'danger',token:A2,password:'pass12345',op:'open'});ok('works after wait',r.ok,r);
 
 section('Danger zone');
{const A=(await call({action:'login',password:'pass12345'})).token;
 const P='pass12345';const D=(o)=>call(Object.assign({action:'danger',token:A,password:P},o));
 let r=await call({action:'staffSave',token:A,k:'cyber',name:'Lead Person',phone:'0715555555',role:'owner',password:'lead12345'});
 r=await call({action:'staffSave',token:A,kind:'coord',name:'Second Coord',phone:'0718888888',password:'coord1234'});
 const L=(await call({action:'login',phone:'0715555555',password:'lead12345'})).token, Co=(await call({action:'login',phone:'0718888888',password:'coord1234'})).token;
 ok('lead login',!!L);ok('coord login',!!Co);
 r=await call({action:'danger',token:L,password:P,op:'open'});ok('lead refused',!r.ok,r);
 r=await call({action:'danger',token:Co,password:P,op:'open'});ok('coord refused',!r.ok,r);
 r=await D({op:'open',password:'wrong'});ok('wrong pw refused',!r.ok&&r.reason==='password',r);await new Promise(z=>setTimeout(z,2200));
 r=await D({op:'open'});ok('open',r.ok&&r.classes.length>=1,r);
 r=await call({action:'student',token:A,k:'cyber',name:'Kamal Perera',phone:'0771111111'});ok('add student',r.ok,r);
 r=await D({op:'db',db:'cyber',q:{op:'tables'}});ok('class tables',r.ok&&r.tables.some(t=>t.name==='t_students'),r);
 r=await D({op:'db',db:'corner',q:{op:'tables'}});ok('corner tables',r.ok&&r.tables.some(t=>t.name==='audit'),r);
 r=await D({op:'db',db:'cyber',q:{op:'rows',table:'t_students'}});ok('rows',r.ok&&r.total>=1,r);
 const row=r.rows.find(x=>x.name==='Kamal Perera');
 r=await D({op:'db',db:'cyber',q:{op:'cell',table:'t_students',rowid:row._rowid,col:'name',value:'Kamal Edited'}});ok('cell edit',r.ok&&r.row.name==='Kamal Edited',r);
 r=await call({action:'data',token:A,k:'cyber'});ok('class sees edit (cache cleared)',r.ok&&r.students.some(s=>s.name==='Kamal Edited'),r);
 r=await D({op:'db',db:'corner',q:{op:'rows',table:'people',find:'Kamal'}});ok('corner people synced',r.ok&&r.rows.some(p=>p.name==='Kamal Edited'),r);
 r=await D({op:'db',db:'cyber',q:{op:'sql',sql:"SELECT COUNT(*) AS n FROM t_students"}});ok('sql select',r.ok&&r.rows[0].n>=1&&r.written===0,r);
 r=await D({op:'db',db:'cyber',q:{op:'sql',sql:"UPDATE t_students SET name='Kamal Sql' WHERE phone='0771111111'"}});ok('sql update',r.ok&&r.written>=1,r);
 r=await call({action:'data',token:A,k:'cyber'});ok('class sees sql edit',r.students.some(s=>s.name==='Kamal Sql'),r);
 r=await D({op:'db',db:'cyber',q:{op:'sql',sql:"SELEC nonsense"}});ok('bad sql message',!r.ok&&/database said/.test(r.message),r);
 r=await D({op:'db',db:'cyber',q:{op:'add',table:'t_excuses',values:{date:'2026-10-01',id:'X',reason:'test'}}});ok('add row',r.ok&&r.rowid>0,r);
 r=await D({op:'db',db:'cyber',q:{op:'del',table:'t_excuses',rowid:r.rowid}});ok('del row',r.ok,r);
 r=await D({op:'points',db:'cyber'});ok('backup made before change',r.ok&&r.points.some(b=>/Danger/.test(b.why)),r);
 r=await D({op:'db',db:'cyber',q:{op:'rows',table:'backups'}});ok('restore points are not editable by hand',!r.ok,r);
 r=await D({op:'prune',db:'cyber',logDays:0,backupsKept:''});ok('prune keeps backups when blank',r.ok&&r.n.backups===0,r);
 r=await D({op:'prune',db:'cyber',backupsKept:0});ok('prune backups',r.ok&&r.n.backups>=1,r);
 r=await D({op:'prune',db:'corner'});ok('prune corner',r.ok,r);
 r=await D({op:'rotateQr',db:'cyber'});ok('rotate qr',r.ok,r);
 r=await D({op:'clearAttendance',db:'cyber',confirm:'nope'});ok('clear needs name',!r.ok,r);
 r=await D({op:'clearAttendance',db:'cyber',confirm:'cyber security'});ok('clear attendance',r.ok,r);
 r=await call({action:'data',token:A,k:'cyber'});ok('students kept',r.students.length>=1&&r.attendance.length===0,r);
 r=await D({op:'unlockAll'});ok('unlock',r.ok,r);
 r=await D({op:'open'});ok('audit list',r.audit.length>=5,r);console.log(r.audit.map(a=>a.what).join(' | '));
 r=await D({op:'signOutAll',confirm:'x'});ok('signout needs confirm',!r.ok,r);
 r=await D({op:'signOutAll',confirm:'sign out'});ok('signout',r.ok,r);
 r=await call({action:'data',token:L,k:'cyber'});ok('lead signed out',!r.ok&&r.reason==='auth',r);
 r=await call({action:'data',token:A,k:'cyber'});ok('admin kept',r.ok,r);
 r=await call({action:'classSave',token:A,name:'Old Class',active:false});ok('archived class',r.ok,r);
 r=await D({op:'deleteArchived',confirm:'DELETE'});ok('delete archived',r.ok&&r.deleted.includes('Old Class'),r);
 }

 section('Student app');
{const A=(await call({action:'login',password:'pass12345'})).token;const crypto=require('crypto');
 const codeOf=(key,ms)=>{const b=crypto.createHmac('sha256',key).update('att:'+Math.floor(ms/30000)).digest();let o='';for(let i=0;i<6;i++)o+='ABCDEFGHJKLMNPQRSTUVWXYZ23456789'[b[i]&31];return o};
 let r=await call({action:'stuLoginSet',token:A,on:true});ok('app sign-in on',r.ok&&r.on,r);
 r=await call({action:'status'});ok('status says accounts',r.accounts===true,r);
 r=await call({action:'lookup',phone:'0751112222',device:'devnimal01'});ok('anonymous check-in refused',r.reason==='signin',r);
 // two classes open now with codes: the code decides
 const mk=async n=>(await call({action:'classSave',token:A,name:n})).class.id;
 const c1=await mk('App One'),c2=await mk('App Two');
 const base=(await call({action:'data',token:A,k:c1})).settings;
 for(const k of [c1,c2]){await call({action:'settings',token:A,k,settings:Object.assign({},base,{requireCode:true,selfRegister:true})});await call({action:'extra',token:A,k,minutes:30})}
 r=await call({action:'student',token:A,k:c1,name:'Sahan Silva',phone:'0761234567'});ok('on class list',r.ok,r);
 r=await call({action:'accRequest',phone:'0761234567',name:'Sahan Silva'});ok('key request',r.ok,r);
 r=await call({action:'accRequest',phone:'0761234567',name:'Sahan Silva'});ok('asking again is fine',r.ok,r);
 r=await call({action:'accRequest',phone:'0716666666',name:'Coord Person'});ok('staff number refused',!r.ok&&r.reason==='staff',r);
 r=await call({action:'stuInbox',token:A});const rq=(r.requests||[]).filter(x=>x.phone==='0761234567');
 ok('one request in the inbox, with who it is',rq.length===1&&rq[0].who.name==='Sahan Silva'&&rq[0].who.classes.length===1&&rq[0].code.length===8,r);
 r=await call({action:'data',token:A,k:c1});ok('admin sees the count',r.corner.stuReq>=1,r.corner);
 r=await call({action:'accActivate',phone:'0761234567',code:'AAAAAAAA',password:'secret-one'});ok('wrong key',!r.ok&&r.reason==='key',r);
 r=await call({action:'accActivate',phone:'0761234567',code:rq[0].code,password:'123'});ok('short password',!r.ok,r);
 r=await call({action:'accActivate',phone:'0761234567',code:rq[0].code,password:'secret-one'});ok('activated',r.ok&&r.token&&r.me.name==='Sahan Silva',r);let T=r.token;
 r=await call({action:'accActivate',phone:'0761234567',code:rq[0].code,password:'secret-two'});ok('key works once',!r.ok,r);
 r=await call({action:'accLogin',phone:'0761234567',password:'nope'});ok('wrong password',!r.ok,r);
 r=await call({action:'accLogin',phone:'0761234567',password:'secret-one'});ok('sign in',r.ok&&r.token,r);const T2=r.token;
 r=await call({action:'app',token:T});ok('home: one class',r.ok&&r.classes.length===1&&r.classes[0].k===c1,r);
 r=await call({action:'app',token:'0'.repeat(40)});ok('bad token',r.reason==='signin',r);
 // check in with the code of class 1: no class picked
 const k1=(await call({action:'data',token:A,k:c1})).qrKey,k2=(await call({action:'data',token:A,k:c2})).qrKey;
 r=await call({action:'appFind',token:T,code:codeOf(k1,Date.now()),device:'devsahan001'});ok('code finds class 1',r.ok&&r.k===c1&&!r.join&&r.student.name==='Sahan Silva',r);
 let f=r;r=await call({action:'appCheckin',token:T,k:f.k,ticket:f.ticket,device:'devsahan001'});ok('checked in',r.ok&&!r.already,r);
 r=await call({action:'appFind',token:T,code:codeOf(k1,Date.now()),device:'devsahan001'});ok('already',r.ok&&!!r.already,r);
 r=await call({action:'appFind',token:T,code:'ZZZZZZ',device:'devsahan001'});ok('wrong code',!r.ok&&r.reason==='code',r);
 r=await call({action:'appFind',token:T,code:'',device:'devsahan001'});ok('no code: asks for it',!r.ok&&r.reason==='code',r);
 // class 2's code: they join it
 r=await call({action:'appFind',token:T,code:codeOf(k2,Date.now()),device:'devsahan001'});ok('code finds class 2: join',r.ok&&r.k===c2&&r.join,r);
 f=r;r=await call({action:'appCheckin',token:T,k:f.k,ticket:f.ticket,join:true,device:'devsahan001'});ok('joined and checked in',r.ok&&r.student&&r.student.name==='Sahan Silva',r);
 r=await call({action:'app',token:T});ok('home: two classes, present',r.classes.length===2&&r.classes.every(c=>c.records.some(x=>x.status==='present')),r.classes);
 // excuses: the student sends, the facilitator accepts
 const day=new Date(Date.now()+7*864e5+330*60000).toISOString().slice(0,10);
 r=await call({action:'appExcuse',token:T,k:c1,date:day,reason:'Exam at school'});ok('excuse sent',r.ok&&r.request.status==='new',r);
 r=await call({action:'appExcuse',token:T,k:c1,date:day,reason:'Exam at school'});ok('same day twice refused',!r.ok,r);
 r=await call({action:'appExcuse',token:T,k:'nope',date:day,reason:'x y z'});ok('not their class',!r.ok,r);
 r=await call({action:'data',token:A,k:c1});const xr=(r.xreq||[]).find(x=>x.date===day);ok('facilitator sees it',!!xr,r.xreq);
 r=await call({action:'excuseReq',token:A,k:c1,rid:xr.rid,accept:true});ok('accepted',r.ok&&r.request.status==='accepted',r);
 r=await call({action:'data',token:A,k:c1});ok('in the class excuses',r.excuses.some(e=>e.date===day),r.excuses);
 r=await call({action:'app',token:T});ok('student sees accepted',r.requests.some(x=>x.date===day&&x.status==='accepted')&&r.classes.find(c=>c.k===c1).upcomingExcuses.includes(day),r);
 // profile: name and password
 r=await call({action:'appSave',token:T,name:'Sahan Kumara Silva'});ok('renamed',r.ok&&r.me.name==='Sahan Kumara Silva',r);
 r=await call({action:'data',token:A,k:c2});ok('new name in the class',r.students.some(s=>s.name==='Sahan Kumara Silva'),r.students);
 r=await call({action:'appSave',token:T,password:'secret-nine',oldPassword:'secret-one'});ok('password changed',r.ok&&r.token,r);const T3=r.token;
 r=await call({action:'app',token:T2});ok('other phone signed out',r.reason==='signin',r);
 r=await call({action:'app',token:T3});ok('this phone kept',r.ok,r);
 // a new number: records are not there; the student tells the admin, the admin moves them
 r=await call({action:'stuKey',token:A,phone:'0769999999',name:'Sahan New Sim'});ok('admin gives a key',r.ok&&r.request.code,r);
 r=await call({action:'accActivate',phone:'0769999999',code:r.request.code,password:'newnum-one'});ok('new number signs in',r.ok,r);const N=r.token;
 // they also registered again in class 1 with the new number (a second student ID)
 r=await call({action:'student',token:A,k:c1,name:'Sahan Kumara Silva',phone:'0769999999'});ok('second ID in class 1',r.ok,r);
 r=await call({action:'app',token:N});ok('new number: only the new ID',r.classes.length===1,r.classes);
 r=await call({action:'appHelp',token:N,other:'0761234567',note:'I changed my SIM'});ok('help sent',r.ok,r);
 r=await call({action:'stuInbox',token:A});const hq=r.requests.find(x=>x.kind==='help'&&x.phone==='0769999999');ok('help in the inbox with the old number',hq&&hq.was&&hq.was.classes.length===2,hq);
 const Cx=(await call({action:'login',phone:'0716666666',password:'coordpass1'})).token;r=await call({action:'stuMove',token:Cx,from:'0761234567',to:'0769999999'});ok('coordinator cannot move',!r.ok,r);
 r=await call({action:'stuReq',token:A,rid:hq.rid,status:'done'});ok('mark done refused while the old number is on a list',!r.ok&&r.reason==='move',r);
 r=await call({action:'stuMoveCheck',token:A,from:'0761234567',to:'0769999999'});ok('check shows both records',r.ok&&r.from.classes.length===2&&r.from.name==='Sahan Kumara Silva'&&r.to.classes.length===1&&r.to.account,r);
 r=await call({action:'stuMove',token:A,from:'0761234567',to:'0769999999',rid:hq.rid});ok('moved',r.ok&&r.moved.length===2,r);
 r=await call({action:'data',token:A,k:c1});const s1=r.students.filter(s=>s.phone==='0769999999');ok('class 1: one student, new number, check-in kept',s1.length===1&&!r.students.some(s=>s.phone==='0761234567')&&r.attendance.some(x=>x.id===s1[0].id),r.students);
 r=await call({action:'app',token:N});ok('app shows the class list name, not the key request name',r.me&&r.me.name==='Sahan Kumara Silva',r.me);
 ok('new number sees both classes and history',r.ok&&r.classes.length===2&&r.classes.every(c=>c.records.some(x=>x.status==='present')),r.classes);
 r=await call({action:'app',token:T3});ok('old number signed out',r.reason==='signin',r);
 r=await call({action:'stuMoveCheck',token:A,from:'0761234567',to:'0769999999'});ok('old number gone after the move',r.ok&&!r.from.classes.length&&!r.from.account&&r.to.classes.length===2,r);
 r=await call({action:'stuInbox',token:A});ok('help marked done',r.requests.find(x=>x.rid===hq.rid).status==='done',r);
 r=await call({action:'appLogout',token:N});r=await call({action:'app',token:N});ok('sign out',r.reason==='signin',r);
 for(const k of [c1,c2])await call({action:'extra',token:A,k,minutes:0});
 }

 section('First sign-in with the mobile number (admin switch)');
{const A=(await call({action:'login',password:'pass12345'})).token;
 const Cx=(await call({action:'login',phone:'0716666666',password:'coordpass1'})).token;
 let r=await call({action:'stuInbox',token:A});ok('off by default, class lists only',r.phoneKey&&r.phoneKey.on===false&&r.phoneKey.known===true,r.phoneKey);
 r=await call({action:'status'});ok('status: off',r.phoneKey===false,r);
 await call({action:'student',token:A,k:'cyber',name:'Nadeesha Perera',phone:'0778880001'});
 r=await call({action:'accFirst',phone:'0778880001',password:'green-leaf-7'});ok('refused while off',!r.ok&&r.reason==='off',r);
 r=await call({action:'phoneKeySet',token:Cx,on:true});ok('coordinator cannot turn it on',!r.ok,r);
 r=await call({action:'phoneKeySet',token:A,on:true});ok('admin turns it on',r.ok&&r.phoneKey.on&&r.phoneKey.known,r);
 r=await call({action:'status'});ok('status: on',r.phoneKey===true,r);
 // a WhatsApp key already waiting for this number: used up by the first sign-in
 const wk=(await call({action:'stuKey',token:A,phone:'0778880001'})).request;
 r=await call({action:'accFirst',phone:'0778880001',password:'12345678'});ok('weak password refused',!r.ok&&r.reason==='password',r);
 r=await call({action:'accFirst',phone:'0778880001',password:'green-leaf-7'});ok('number on a class list signs in',r.ok&&r.token&&r.trust&&r.me.name==='Nadeesha Perera',r);const P=r.token;
 r=await call({action:'app',token:P});ok('signed in home',r.ok&&r.classes.length===1,r);
 r=await call({action:'stuInbox',token:A});ok('waiting WhatsApp key is used up',r.requests.find(x=>x.rid===wk.rid).status==='used',r);
 r=await call({action:'accFirst',phone:'0778880001',password:'other-pass-9'});const m1=r.message;ok('only once: account exists',!r.ok&&r.reason==='number',r);
 r=await call({action:'accLogin',phone:'0778880001',password:'green-leaf-7'});ok('then the password',r.ok,r);
 r=await call({action:'accFirst',phone:'0778880999',password:'green-leaf-7'});ok('number not on a class list refused, same answer',!r.ok&&r.reason==='number'&&r.message===m1,r);
 r=await call({action:'accFirst',phone:'0716666666',password:'green-leaf-7'});ok('facilitator number refused',!r.ok&&r.reason==='number',r);
 // the WhatsApp key still works and takes the number back (someone else signed in first)
 const k2=(await call({action:'stuKey',token:A,phone:'0778880001'})).request.code;
 r=await call({action:'accActivate',phone:'0778880001',code:k2,password:'real-owner-3'});ok('WhatsApp key still works',r.ok,r);
 r=await call({action:'app',token:P});ok('the first sign-in is signed out',r.reason==='signin',r);
 // any number, with a name, when the admin allows it
 r=await call({action:'phoneKeySet',token:A,known:false});ok('any number allowed',r.ok&&r.phoneKey.on&&!r.phoneKey.known,r);
 r=await call({action:'accFirst',phone:'0778880999',password:'green-leaf-7'});ok('not on a list: asks for a name',!r.ok&&r.reason==='name',r);
 r=await call({action:'accFirst',phone:'0778880999',password:'green-leaf-7',name:'Kasun Fernando'});ok('signs in with a name',r.ok&&r.me.name==='Kasun Fernando',r);
 // tries are limited per number and per address
 for(let i=0;i<7;i++)r=await callFrom('10.5.5.5',{action:'accFirst',phone:'0778880002',password:'x'});ok('per number limit',r.reason==='slow',r);
 for(let i=0;i<22;i++)r=await callFrom('10.5.5.6',{action:'accFirst',phone:'07788810'+String(i).padStart(2,'0'),password:'x'});ok('per address limit',r.reason==='slow',r);
 r=await call({action:'changes',token:A,find:'first sign-in'});ok('in the change log',r.ok&&r.rows.length>0,r);
 r=await call({action:'phoneKeySet',token:A,on:false,known:true});ok('admin turns it off',r.ok&&!r.phoneKey.on,r);
 r=await call({action:'accFirst',phone:'0778880003',password:'green-leaf-7'});ok('off again',r.reason==='off',r);
 }

 section('Main password');
{const A=(await call({action:'login',password:'pass12345'})).token,B=(await call({action:'login',password:'pass12345'})).token;
 await call({action:'staffSave',token:A,k:'cyber',name:'Owner Person',phone:'0711111111',role:'owner',password:'owner123'});let F=(await call({action:'login',phone:'0711111111',password:'owner123'})).token;await call({action:'myAccount',token:F,name:'Owner Person',password:'owner1234',oldPassword:'owner123'});F=(await call({action:'login',phone:'0711111111',password:'owner1234'})).token;
 let r=await call({action:'adminPassword',token:A,oldPassword:'wrong',password:'newpass123'});ok('wrong old refused',!r.ok,r);
 r=await call({action:'adminPassword',token:F,oldPassword:'owner1234',password:'newpass123'});ok('facilitator refused',!r.ok,r);
 r=await call({action:'adminPassword',token:A,oldPassword:'pass12345',password:'short'});ok('short refused',!r.ok,r);
 r=await call({action:'adminPassword',token:A,oldPassword:'pass12345',password:'newpass123'});ok('changed',r.ok,r);
 r=await call({action:'data',token:A,k:'cyber'});ok('this admin sign-in kept',r.ok,r);
 r=await call({action:'data',token:B,k:'cyber'});ok('other admin sign-in ended',!r.ok&&r.reason==='auth',r);
 r=await call({action:'data',token:F,k:'cyber'});ok('facilitator still signed in',r.ok,r);
 r=await call({action:'login',password:'pass12345'});ok('old password refused',!r.ok,r);
 r=await call({action:'login',password:'newpass123'});ok('new password works',r.ok,r);
 r=await call({action:'adminPassword',token:r.token,oldPassword:'newpass123',password:'pass12345'});ok('changed back',r.ok,r);
 }


 section('Admin and facilitator with the same password');
{const A=(await call({action:'login',password:'pass12345'})).token;
 await call({action:'staffSave',token:A,k:'cyber',name:'Same Password',phone:'0712223344',role:'instructor',password:'start123'});
 let F=(await call({action:'login',phone:'0712223344',password:'start123'})).token;
 let r=await call({action:'myAccount',token:F,name:'Same Password',password:'pass12345',oldPassword:'start123'});ok('facilitator picks the admin password',r.ok,r);
 r=await call({action:'login',as:'admin',password:'pass12345'});ok('admin sign-in is the admin',r.ok&&r.corner.admin&&!r.me,r);
 r=await call({action:'login',as:'admin',phone:'0712223344',password:'pass12345'});ok('admin sign-in with a stray number is still the admin',r.ok&&r.corner.admin&&!r.me,r);
 r=await call({action:'login',as:'staff',phone:'0712223344',password:'pass12345'});ok('facilitator sign-in is the facilitator',r.ok&&!r.corner.admin&&r.me&&r.me.phone==='0712223344',r);
 r=await call({action:'data',token:r.token,k:'cyber'});ok('facilitator gets no admin rights',r.ok&&!r.corner.admin,r.corner);
 r=await call({action:'login',as:'staff',password:'pass12345'});ok('facilitator sign-in without a number is refused',!r.ok&&!r.token,r);
 r=await call({action:'login',phone:'0712223344',password:'pass12345'});ok('older page: number means facilitator',r.ok&&!r.corner.admin&&r.me,r);
 r=await call({action:'login',password:'pass12345'});ok('older page: no number means admin',r.ok&&r.corner.admin&&!r.me,r);
 F=(await call({action:'login',as:'staff',phone:'0712223344',password:'pass12345'})).token;
 r=await call({action:'staffSave',token:A,sid:(await call({action:'data',token:F,k:'cyber'})).me.id,remove:true,k:'cyber'});
 }

 section('Security: lockouts, passwords, change log, restore points');
 {
 const A=(await call({action:'login',password:'pass12345'})).token;
 // wrong server keys from a student's address lock only that address
 for(let i=0;i<11;i++)r=await callFrom('10.9.9.9',{action:'maint',key:'guess'+i,op:'check'});ok('wrong server keys lock that address',r.reason==='locked',r);
 r=await callFrom('10.1.1.1',{action:'maint',key:KEY,op:'check'});ok('the admin elsewhere still gets in',r.ok,r);
 r=await call({action:'maint',key:[KEY],op:'check'});ok('server key must be text',!r.ok,r);
 // student app: weak passwords, a classmate can't lock a phone that signed in before, the same answer for any number
 await call({action:'student',token:A,k:'cyber',name:'Ruwan Jayasuriya',phone:'0745550001'});
 let kq=(await call({action:'stuKey',token:A,phone:'0745550001',name:'Ruwan Jayasuriya'})).request.code;
 for(const pw of ['short1','12345678','password1','aaaaaaaa','x0745550001'])r=await call({action:'accActivate',phone:'0745550001',code:kq,password:pw}),ok('weak password refused: '+pw,!r.ok&&r.reason==='password',r);
 r=await call({action:'accActivate',phone:'0745550001',code:kq,password:'blue-river-42'});ok('good password',r.ok&&r.trust,r);const ST=r.token,TR=r.trust;
 for(let i=0;i<11;i++)r=await callFrom('10.7.7.7',{action:'accLogin',phone:'0745550001',password:'nope'+i});ok('classmate locked a new phone',r.reason==='locked',r);
 r=await callFrom('10.8.8.8',{action:'accLogin',phone:'0745550001',password:'blue-river-42',trust:TR});ok('own phone still signs in',r.ok,r);
 const m1=(await call({action:'accLogin',phone:'0745559999',password:'whatever1'})).message,m2=(await callFrom('10.6.6.6',{action:'accLogin',phone:'0761234567',password:'whatever1'})).message;
 ok('same answer with or without an account',m1===m2,[m1,m2]);
 let saves=0;for(let i=0;i<35;i++){r=await call({action:'appSave',token:ST,name:i%2?'Ruwan Jayasuriya':'Ruwan Jayasooriya'});if(r.ok)saves++}
 ok('profile saves are limited',saves<=30&&r.reason==='slow',saves);
 // change log: what changed, by whom, sealed; the Danger zone can't reach it
 await call({action:'student',token:A,k:'cyber',name:'Log Test One',phone:'0745550002'});
 r=await call({action:'changes',token:A,find:'Log Test One'});
 const row=r.rows&&r.rows.find(x=>x.place==='Cyber Security'&&/^students /.test(x.target));
 ok('change log has the new student',row&&row.op==='add'&&row.role==='admin'&&row.ok===true,r.rows&&r.rows.slice(0,3));
 r=await call({action:'changes',token:A,kind:'alert'});ok('failed tries are listed with the address',r.rows.some(x=>x.ip==='10.9.9.9'&&x.target==='server key')&&r.rows.some(x=>x.ip==='10.7.7.7'),r.rows.slice(0,3));
 r=await call({action:'changes',token:A,find:'0745550001',kind:'change'});ok('a student password is never shown',r.rows.length&&!JSON.stringify(r.rows).includes('blue-river')&&!/"hash":"[a-f0-9]{20,}/.test(JSON.stringify(r.rows)),r.rows.slice(0,2));
 const F2=(await call({action:'login',phone:'0711111111',password:'owner1234'})).token;
 r=await call({action:'changes',token:F2});ok('a facilitator cannot read the change log',!r.ok,r);
 for(const q of ['DELETE FROM changes','UPDATE changes SET who = 1','DROP TRIGGER changes_keep_d','SELECT * FROM sqlite_master','PRAGMA writable_schema = 1'])
   r=await call({action:'danger',token:A,password:'pass12345',op:'db',db:'corner',q:{op:'sql',sql:q}}),ok('refused: '+q,!r.ok,r);
 r=await call({action:'danger',token:A,password:'pass12345',op:'db',db:'corner',q:{op:'tables'}});ok('the editor does not list the log',r.ok&&!r.tables.some(t=>/^(changes|chg_)/.test(t.name)),r.tables&&r.tables.map(t=>t.name));
 r=await call({action:'danger',token:A,password:'pass12345',op:'db',db:'corner',q:{op:'rows',table:'changes'}});ok('the editor cannot open the log',!r.ok,r);
 let ck={next:1};for(;;){ck=await call({action:'changesCheck',token:A,from:ck.next});if(!ck.ok||ck.broken||ck.done)break}
 ok('the whole chain checks out',ck.ok&&ck.done&&!ck.broken,ck);
 // restore points: a class and the Corner go back, and going back can be undone
 r=await call({action:'danger',token:A,password:'pass12345',op:'point',db:'cyber',why:'before the test'});ok('class restore point',r.ok,r);
 const sid=(await call({action:'data',token:A,k:'cyber'})).students.find(x=>x.phone==='0745550002').id;
 await call({action:'student',token:A,k:'cyber',id:sid,name:'Changed Later',phone:'0745550002'});
 r=await call({action:'danger',token:A,password:'pass12345',op:'points',db:'cyber'});const pt=r.points.find(x=>x.why==='before the test');ok('listed',!!pt,r);
 r=await call({action:'danger',token:A,password:'pass12345',op:'restore',db:'cyber',id:pt.id,confirm:'nope'});ok('needs RESTORE',!r.ok,r);
 r=await call({action:'danger',token:A,password:'pass12345',op:'restore',db:'cyber',id:pt.id,confirm:'RESTORE'});ok('class went back',r.ok,r);
 r=await call({action:'data',token:A,k:'cyber'});ok('name is back',r.students.find(x=>x.id===sid).name==='Log Test One',r.students.find(x=>x.id===sid));
 r=await call({action:'danger',token:A,password:'pass12345',op:'points',db:'cyber'});ok('a restore point of just before was made',/^Before going back/.test(r.points[0].why),r.points[0]);
 r=await call({action:'changes',token:A,find:'restored'});ok('the restore is in the change log',r.rows.some(x=>x.place==='Cyber Security'),r.rows.slice(0,2));
 r=await call({action:'danger',token:A,password:'pass12345',op:'point',db:'corner',why:'corner test'});ok('Corner restore point',r.ok,r);
 await call({action:'staffSave',token:A,name:'Temp Person',phone:'0745550003',password:'start123',k:'cyber',role:'instructor'});
 r=await call({action:'people',token:A});
 const cp=(await call({action:'danger',token:A,password:'pass12345',op:'points',db:'corner'})).points.find(x=>x.why==='corner test');
 r=await call({action:'danger',token:A,password:'pass12345',op:'restore',db:'corner',id:cp.id,confirm:'RESTORE'});ok('Corner went back',r.ok,r);
 r=await call({action:'login',phone:'0745550003',password:'start123'});ok('account made after it is gone',!r.ok,r);
 r=await call({action:'data',token:A,k:'cyber'});ok('admin still signed in after a restore',r.ok,r);
 r=await call({action:'danger',token:F2,password:'pass12345',op:'points',db:'corner'});ok('facilitator cannot use restore points',!r.ok,r);
 }
 section('WhatsApp helper');
{const A=(await call({action:'login',password:'pass12345'})).token;
 const H=b=>call(Object.assign({helperKey:HK},b));let HK='';
 let r=await call({action:'stuInbox',token:A});ok('inbox shows the helper, off, no key',r.wa&&r.wa.on===false&&r.wa.hasKey===false,r.wa);
 r=await call({action:'waSave',token:A,cfg:{on:true}});ok('cannot turn on without the app link',!r.ok,r);
 r=await call({action:'waSave',token:A,cfg:{base:'javascript:alert(1)'}});ok('bad link refused',!r.ok,r);
 r=await call({action:'waSave',token:A,cfg:{on:true,base:'https://example.org/attendance.html?s=x',perHour:99,perDay:999,gap:0,from:'00:00',to:'23:59',known:true},newKey:true});
 ok('turned on, limits capped',r.ok&&r.wa.on&&r.wa.perHour===10&&r.wa.perDay===40&&r.wa.gap===2,r.wa);ok('key shown once',/^wa_[a-f0-9]{48}$/.test(r.key),r);HK=r.key;
 r=await call({action:'stuInbox',token:A});ok('key not shown again',r.wa.hasKey&&!JSON.stringify(r).includes(HK),r.wa);
 const L=(await call({action:'login',phone:'0715555555',password:'lead12345'})).token;
 r=await call({action:'waSave',token:L,cfg:{on:false}});ok('a facilitator cannot change it',!r.ok,r);
 r=await callFrom('10.9.9.9',{action:'waNext',helperKey:'wa_'+'0'.repeat(48)});ok('wrong helper key',!r.ok&&r.reason==='key',r);
 r=await H({action:'waNext',token:A});ok('helper key is not a sign-in',r.ok,r);
 r=await H({action:'data',k:'cyber'});ok('helper key opens nothing else',!r.ok&&r.reason==='auth',r);
 r=await H({action:'stuInbox'});ok('helper cannot read the inbox',!r.ok,r);
 // two students ask: one on a class list, one not
 await call({action:'student',token:A,k:'cyber',name:'Wa Known',phone:'0742220001'});
 r=await call({action:'accRequest',phone:'0742220001',name:'Wa Known'});ok('known asks',r.ok,r);
 r=await call({action:'accRequest',phone:'0742220002',name:'Wa Stranger'});ok('stranger asks',r.ok,r);
 r=await H({action:'waNext'});ok('a request under a minute old waits',r.ok&&r.wait&&!r.rid,r);
 await call({action:'danger',token:A,password:'pass12345',op:'db',db:'corner',q:{op:'sql',sql:"UPDATE areq SET at = at - 120000 WHERE phone IN ('0742220001','0742220002')"}});
 r=await H({action:'waNext'});ok('next: the known student only',r.ok&&r.to==='94742220001'&&r.text.includes('https://example.org/attendance.html?s=x&key=0742220001.'),r);const n1=r;
 r=await H({action:'waNext'});ok('one at a time',r.ok&&r.wait&&!r.rid,r);
 r=await H({action:'waDone',rid:n1.rid,claim:'nope',sent:true});ok('wrong claim refused',!r.ok,r);
 r=await H({action:'waDone',rid:n1.rid,claim:n1.claim,sent:true});ok('sent',r.ok,r);
 r=await call({action:'stuInbox',token:A});const q1=r.requests.find(x=>x.rid===n1.rid);ok('marked sent by the helper',q1.status==='sent'&&q1.by==='WhatsApp helper',q1);ok('counted',r.wa.day===1&&r.wa.seen>0,r.wa);
 r=await H({action:'waNext'});ok('minutes between messages',r.ok&&r.wait>=30&&/between/.test(r.why),r);
 r=await call({action:'changes',token:A,find:'WhatsApp helper'});
 ok('the change log has the key taken, the send and the wrong key',r.rows.some(x=>x.op==='helper took key')&&r.rows.some(x=>x.role==='helper'&&/sent/.test(x.after))&&r.rows.some(x=>x.kind==='alert'&&/wrong helper key/.test(x.after)),r.rows.slice(0,5));
 ok('the code is never in the log',!JSON.stringify(r.rows).includes(n1.text.match(/\*(\w{4})-(\w{4})\*/).slice(1).join('')),'');
 r=await call({action:'waSave',token:A,cfg:{on:false}});ok('off',r.ok&&!r.wa.on,r);
 r=await H({action:'waNext'});ok('off: nothing',!r.ok&&r.reason==='off',r);
 r=await call({action:'waSave',token:A,cfg:{on:true},revoke:true});ok('key stopped',r.ok&&!r.wa.hasKey,r);
 r=await H({action:'waNext'});ok('old key refused',!r.ok&&r.reason==='key',r);
 await call({action:'waSave',token:A,cfg:{on:false}});
 }
 section('Firebase key queue');
{const A=(await call({action:'login',password:'pass12345'})).token;
 // a stand-in for the Firebase Realtime Database REST API (the Worker's .dev.vars point FIREBASE_URL here)
 const http=require('http');const tree={};let badAuth=0,tokens=0;
 let SA=null;try{const m=fs.readFileSync(__dirname+'/../.dev.vars','utf8').match(/FIREBASE_SERVICE_ACCOUNT='(.*)'/);if(m)SA=JSON.parse(m[1])}catch(e){}
 const fbsrv=http.createServer((q,s)=>{let b='';q.on('data',d=>b+=d);q.on('end',()=>{const u=new URL(q.url,'http://x');
   // Google's token endpoint: the JWT must be signed by the service account's key, for the database scope
   if(u.pathname==='/token'){const jwt=new URLSearchParams(b).get('assertion')||'',[h,c,g]=jwt.split('.');
     const good=SA&&require('crypto').verify('RSA-SHA256',Buffer.from(h+'.'+c),require('crypto').createPublicKey(SA.private_key),Buffer.from(g||'','base64url'));
     const cl=JSON.parse(Buffer.from(c||'','base64url').toString()||'{}');
     if(!good||cl.iss!==SA.client_email||!/firebase\.database/.test(cl.scope)){badAuth++;s.writeHead(400);return s.end('{}')}
     tokens++;s.writeHead(200,{'content-type':'application/json'});return s.end(JSON.stringify({access_token:'tok-'+tokens,expires_in:3600}))}
   if(u.searchParams.get('auth')!=='ci-firebase-secret'&&!/^tok-\d+$/.test(u.searchParams.get('access_token')||'')){badAuth++;s.writeHead(401);return s.end('null')}
   const key=u.pathname.replace(/^\/keyQueue\//,'').replace(/\.json$/,'');
   if(q.method==='PUT')tree[key]=JSON.parse(b);if(q.method==='DELETE')delete tree[key];
   s.writeHead(200,{'content-type':'application/json'});s.end(JSON.stringify(q.method==='DELETE'?null:tree[key]===undefined?null:tree[key]))})});
 await new Promise(z=>fbsrv.listen(8799,'127.0.0.1',z));
 const tick=async()=>{await fetch(W+'__scheduled?cron='+encodeURIComponent('* * * * *'));await new Promise(z=>setTimeout(z,300))};
 let r=await call({action:'stuInbox',token:A});
 if(!r.wa.firebase){ok('Firebase set up for the test (FIREBASE_URL and FIREBASE_SECRET in .dev.vars)',false,r.wa)}else{
 // the stranger from the helper section is older and would go first: dismissed
 await call({action:'danger',token:A,password:'pass12345',op:'db',db:'corner',q:{op:'sql',sql:"UPDATE areq SET status = 'dismissed' WHERE phone = '0742220002'"}});
 r=await call({action:'waSave',token:A,cfg:{on:true,base:'https://example.org/attendance.html',gap:2,from:'08:00',to:'08:01',known:false}});ok('on',r.ok,r);
 ok('turning on with nothing waiting leaves the slot empty',!tree.current,tree);
 // no tick: asking puts the key in the slot at once, whatever the hours, limits or gap (the helper section sent one just now)
 r=await call({action:'accRequest',phone:'0742220003',name:'Fb Student'});ok('student asks',r.ok,r);
 ok('the key is in the slot at once, pending',tree.current&&tree.current.flag==='pending'&&tree.current.phone==='94742220003'&&tree.current.text.includes('key=0742220003.')&&/^[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(tree.current.key)&&tree.current.link.includes('key=0742220003.')&&tree.current.name==='Fb',tree);
 const rid=tree.current&&tree.current.rid;
 await tick();ok('pending stays while the reader works',tree.current&&tree.current.rid===rid,tree);
 // deleted by hand in the console: the same key goes in again, and the status comes back
 delete tree.current;delete tree.status;await tick();ok('a slot deleted by hand is filled again',tree.current&&tree.current.rid===rid&&tree.current.flag==='pending'&&tree.status,tree);
 delete tree.current;await tick();delete tree.current;await tick();ok('and again (no try limit)',tree.current&&tree.current.rid===rid,tree);
 r=await call({action:'stuInbox',token:A});ok('still new in the app',r.requests.find(x=>x.rid===rid).status==='new'&&r.wa.fb&&/reader|waiting/.test(r.wa.fb.why),r.wa);
 // a second student asks while the first is pending: it waits for the flag
 r=await call({action:'accRequest',phone:'0742220004',name:'Fb Second'});ok('second asks',r.ok,r);ok('first still in the slot',tree.current.rid===rid,tree);
 tree.current.flag='sent';r=await call({action:'fbPoke'});ok('poke',r.ok,r);
 r=await call({action:'stuInbox',token:A});const q=r.requests.find(x=>x.rid===rid);ok('flag sent: marked sent in the app',q.status==='sent'&&q.by==='Firebase queue',q);
 ok('the next key is in at once',tree.current&&tree.current.phone==='94742220004'&&tree.current.flag==='pending',tree);
 tree.current.flag='failed';tree.current.reason='no WhatsApp on this number';await tick();
 r=await call({action:'stuInbox',token:A});ok('failed: stays new with the reason',r.requests.find(x=>x.phone==='0742220004'&&x.status==='new').waErr==='no WhatsApp on this number',r.requests.filter(x=>x.phone==='0742220004'));
 ok('slot emptied, nothing left',!tree.current,tree);
 // a forged slot (not handed out by the server) is thrown away and changes nothing
 tree.current={rid,claim:'forged',flag:'sent'};await tick();ok('forged slot removed',!tree.current||tree.current.rid!==rid,tree);
 r=await call({action:'changes',token:A,find:'Firebase queue'});ok('in the change log',r.rows.some(x=>x.who==='Firebase queue'&&x.op==='helper took key')&&r.rows.some(x=>x.who==='Firebase queue'&&/sent/.test(x.after)),r.rows.slice(0,4));
 r=await call({action:'waSave',token:A,cfg:{on:false}});ok('off: says so',/off/.test(tree.status.why),tree.status);
 ok('never a wrong secret or bad signature',badAuth===0,badAuth);if(SA)ok('one service account token, reused',tokens===1,tokens);}
 fbsrv.close();
 }
 console.log(f ? '\n' + f + ' FAILED' : '\nALL PASS'); process.exit(f ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
