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
