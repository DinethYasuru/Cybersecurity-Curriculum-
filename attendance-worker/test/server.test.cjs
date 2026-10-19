// Attendance server checks: run against `wrangler dev` (see .github/workflows/attendance-tests.yml).
// A fresh local database with the main password pass12345; SETUP_KEY comes from .dev.vars or the environment.
const fs = require('fs');
const W = process.env.ATT_URL || 'http://localhost:8787/';
const KEY = process.env.SETUP_KEY || fs.readFileSync(__dirname + '/../.dev.vars', 'utf8').match(/SETUP_KEY=(.*)/)[1].trim();
const call = async b => (await fetch(W, { method: 'POST', body: JSON.stringify(b) })).json();
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
 r=await D({op:'db',db:'cyber',q:{op:'rows',table:'backups'}});ok('backup made before change',r.ok&&r.rows.some(b=>/Danger/.test(b.why)),r);
 r=await D({op:'db',db:'cyber',q:{op:'rows',table:'backup_parts'}});ok('long values cut',r.ok&&r.rows.every(x=>String(x.data).length<=300)&&r.rows.some(x=>x._cut),r);
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
 r=await call({action:'accActivate',phone:'0761234567',code:'AAAAAAAA',password:'secret1'});ok('wrong key',!r.ok&&r.reason==='key',r);
 r=await call({action:'accActivate',phone:'0761234567',code:rq[0].code,password:'123'});ok('short password',!r.ok,r);
 r=await call({action:'accActivate',phone:'0761234567',code:rq[0].code,password:'secret1'});ok('activated',r.ok&&r.token&&r.me.name==='Sahan Silva',r);let T=r.token;
 r=await call({action:'accActivate',phone:'0761234567',code:rq[0].code,password:'secret2'});ok('key works once',!r.ok,r);
 r=await call({action:'accLogin',phone:'0761234567',password:'nope'});ok('wrong password',!r.ok,r);
 r=await call({action:'accLogin',phone:'0761234567',password:'secret1'});ok('sign in',r.ok&&r.token,r);const T2=r.token;
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
 r=await call({action:'appSave',token:T,password:'secret9',oldPassword:'secret1'});ok('password changed',r.ok&&r.token,r);const T3=r.token;
 r=await call({action:'app',token:T2});ok('other phone signed out',r.reason==='signin',r);
 r=await call({action:'app',token:T3});ok('this phone kept',r.ok,r);
 // a new number: records are not there; the student tells the admin, the admin moves them
 r=await call({action:'stuKey',token:A,phone:'0769999999',name:'Sahan Kumara Silva'});ok('admin gives a key',r.ok&&r.request.code,r);
 r=await call({action:'accActivate',phone:'0769999999',code:r.request.code,password:'newnum1'});ok('new number signs in',r.ok,r);const N=r.token;
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
 r=await call({action:'app',token:N});ok('new number sees both classes and history',r.ok&&r.classes.length===2&&r.classes.every(c=>c.records.some(x=>x.status==='present')),r.classes);
 r=await call({action:'app',token:T3});ok('old number signed out',r.reason==='signin',r);
 r=await call({action:'stuMoveCheck',token:A,from:'0761234567',to:'0769999999'});ok('old number gone after the move',r.ok&&!r.from.classes.length&&!r.from.account&&r.to.classes.length===2,r);
 r=await call({action:'stuInbox',token:A});ok('help marked done',r.requests.find(x=>x.rid===hq.rid).status==='done',r);
 r=await call({action:'appLogout',token:N});r=await call({action:'app',token:N});ok('sign out',r.reason==='signin',r);
 for(const k of [c1,c2])await call({action:'extra',token:A,k,minutes:0});
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

 console.log(f ? '\n' + f + ' FAILED' : '\nALL PASS'); process.exit(f ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
