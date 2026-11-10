import {deleteProtectedLocalAccount} from './protected-local.mjs';
import {TaskBoard,OperationsAdmin} from './Operations';
import {ActivityReview} from './ActivityReview';
import {StaffSecurity} from './StaffSecurity';
import React,{useEffect,useState,FormEvent,createContext,useContext} from 'react';
import {startRegistration,startAuthentication} from '@simplewebauthn/browser';
import {createRoot} from 'react-dom/client';
import {request,ApiError} from './api';
import {forms as worksheetTemplates,worksheet} from '../../../packages/core/forms.mjs';
import {roles as roleDefinitions,recommendRole} from '../../../packages/core/roles.mjs';
import {parseMaterialMarkdown,materialLinks} from '../../../packages/core/material-outline.mjs';
import './portal.css';
import {Coordination} from './Coordination';
import {AdminTreasury} from './AdminTreasury';
import {AdminOperations} from './AdminOperations';
import {AdminVisitors} from './AdminVisitors';
import {Orientation} from './Orientation';
import {HelpCenter} from './HelpCenter';
const ProtectedReports=React.lazy(()=>import('./ProtectedReports').then(m=>({default:m.ProtectedReports})));
type Config={publicOrigin:string;signupEnabled:boolean;adminLoginEnabled:boolean;passkeyEnabled?:boolean;notice:string|null;features:Record<string,boolean>};
type Session={account:{id:string;verified:boolean;marketing:boolean;role:string};csrf:string;expires:number};
type Material={id:string;title:string;description:string;category:string;revision:number;body?:string;reviewedAt?:string;acknowledged?:boolean;readingNotice?:string};
type FormSpec={id:string;title:string;notice:string;restricted:boolean;fields:{name:string;label:string;type:string}[]};
const Context=createContext<{config:Config|null;session:Session|null;refresh:()=>Promise<void>}>({config:null,session:null,refresh:async()=>{}});
function usePath(){const[path,set]=useState(location.pathname);useEffect(()=>{const pop=()=>set(location.pathname);window.addEventListener('popstate',pop);return()=>window.removeEventListener('popstate',pop);},[]);return[path,(p:string)=>{history.pushState({},'',p);set(p);window.dispatchEvent(new PopStateEvent('popstate'));window.scrollTo(0,0);} ]as const;}
function Link({to,children,className='',...props}:{to:string;children:React.ReactNode;className?:string;[key:string]:unknown}){return <a href={to} className={className} {...props} onClick={e=>{if(to.startsWith('/')&&!e.ctrlKey&&!e.metaKey&&!e.shiftKey&&!e.altKey){e.preventDefault();history.pushState({},'',to);window.dispatchEvent(new PopStateEvent('popstate'));window.scrollTo(0,0);}}}>{children}</a>;}
function useLoad<T>(path:string|null){const[data,setData]=useState<T|null>(null),[error,setError]=useState(''),[loading,setLoading]=useState(Boolean(path));useEffect(()=>{setData(null);setError('');if(!path){setLoading(false);return;}const abort=new AbortController();setLoading(true);request<T>(path,undefined,undefined,abort.signal).then(setData).catch(e=>{if(e.name!=='AbortError')setError(e.message);}).finally(()=>{if(!abort.signal.aborted)setLoading(false);});return()=>abort.abort();},[path]);return{data,error,loading};}
function Notice({children,error=false}:{children:React.ReactNode;error?:boolean}){return <div className={'notice'+(error?' error':'')} role={error?'alert':'status'}>{children}</div>;}
function Brand(){const {config}=useContext(Context);return <a href={config?.publicOrigin||'/'} className="brand" aria-label="Galinsky for America campaign"><span className="brand-symbol" aria-hidden="true"/><span><strong>GALINSKY</strong><small>FOR AMERICA &bull; 2028</small></span></a>;}
function Join(){const{config,refresh}=useContext(Context);const[email,setEmail]=useState(''),[terms,setTerms]=useState(false),[marketing,setMarketing]=useState(false),[message,setMessage]=useState(''),[error,setError]=useState(''),[busy,setBusy]=useState(false);async function submit(e:FormEvent){e.preventDefault();if(!(config?.signupEnabled||config?.adminLoginEnabled))return;setBusy(true);setError('');try{const r=await request<{message:string}>('/api/auth/request',{email,termsAccepted:terms,marketing});setMessage(r.message);setEmail('');await refresh();}catch(e){setError((e as Error).message);}finally{setBusy(false);}}
 return <section className="join-layout"><div className="join-copy"><span className="eyebrow">JUSTICE FOR ALL STARTS WITH US.</span><h1>Your time.<br/>Your voice.<br/><em>A way forward.</em></h1><p>One conversation. One shared idea. One manageable action. Find the tools and guidance to make your contribution count.</p><div className="join-principles"><span>Choose your role</span><span>Learn at your pace</span><span>Make your first move</span></div></div><div className="panel"><span className="eyebrow">{config?.adminLoginEnabled&&!config.signupEnabled?'PRIVATE STAFF SIGN-IN':'JOIN THE VOLUNTEER TEAM'}</span><h2>Start here.</h2><p>{config?.adminLoginEnabled&&!config.signupEnabled?'Authorized staff sign in by verifying their registered email address. Public volunteer signup remains disabled.':config?.passkeyEnabled&&!config?.signupEnabled?'Create a volunteer account with your device passkey. Your role, orientation and task progress are saved in the real portal.':'New and returning volunteers use the same email sign-in. No password to remember.'}</p>{config&&!config.signupEnabled&&<Notice>{config.notice} {config.passkeyEnabled?'Email-link registration is not available yet.':'Public volunteer registration remains closed.'}</Notice>}{error&&<Notice error>{error}</Notice>}{message?<Notice>{message}</Notice>:(!config?.passkeyEnabled||config.signupEnabled||config.adminLoginEnabled)?<form onSubmit={submit}><label>Email address<input name="email" type="email" autoComplete="email" required maxLength={254} value={email} onChange={e=>setEmail(e.target.value)} disabled={!(config?.signupEnabled||config?.adminLoginEnabled)||busy}/></label><label className="check"><input type="checkbox" checked={terms} onChange={e=>setTerms(e.target.checked)} required disabled={!(config?.signupEnabled||config?.adminLoginEnabled)||busy}/><span>I have read the <a href={(config?.publicOrigin||'')+'/notices/#terms'}>participation terms</a> and <a href={(config?.publicOrigin||'')+'/notices/#privacy'}>privacy notice</a>. Account access requires service messages.</span></label><label className="check"><input type="checkbox" checked={marketing} onChange={e=>setMarketing(e.target.checked)} disabled={!config?.signupEnabled||busy}/><span>Send optional campaign updates by email. This is not required to volunteer.</span></label><button className="btn" disabled={!(config?.signupEnabled||config?.adminLoginEnabled)||busy}>{busy?'Sending securely...':'Email my sign-in link'} <span aria-hidden="true">&rarr;</span></button><p className="fine">We use your email for account access. Profile details and sensitive submissions are not collected here.</p></form>:null}<PasskeyEntry/><Link to="/roles" className="textlink">Explore the twelve roles &rarr;</Link></div></section>;
}

function PasskeyEntry(){
 const{config,refresh}=useContext(Context);
 const[,navigate]=usePath();
 const[terms,setTerms]=useState(false),[busy,setBusy]=useState(false),[error,setError]=useState('');
 if(!config?.passkeyEnabled)return null;
 async function run(kind:'register'|'authenticate'){
  setBusy(true);setError('');
  try{
   if(!window.PublicKeyCredential||!navigator.credentials)throw new Error('This browser does not support passkeys. Use a current browser or email sign-in.');
   if(kind==='register'&&!terms)throw new Error('Review and accept the participation terms and privacy notice first.');
   const options=await request<{options:Parameters<typeof startRegistration>[0]['optionsJSON']}>('/api/passkeys/'+kind+'/options',{});
   const response=kind==='register'?
    await startRegistration({optionsJSON:options.options}):
    await startAuthentication({optionsJSON:options.options as Parameters<typeof startAuthentication>[0]['optionsJSON']});
   await request('/api/passkeys/'+kind+'/verify',kind==='register'?{response,termsAccepted:true}:{response});
   await refresh();navigate('/');
  }catch(e){setError((e as Error).message||'Passkey authentication failed. Try again.');}
  finally{setBusy(false);}
 }
 return <div className="passkey-entry" aria-label="Volunteer passkey account">
  <h3>Use a passkey instead</h3>
  <p>Create or open your volunteer account with your device's passkey, without waiting for an email message.</p>
  <p className="fine"><strong>Keep your passkey available:</strong> account recovery and replacement-device access are not available for passkey-only accounts yet. Use a passkey synchronized by your trusted device provider if possible.</p>
  <label className="check"><input type="checkbox" checked={terms} onChange={e=>setTerms(e.target.checked)} disabled={busy}/>
   <span>I accept the <a href={config.publicOrigin+'/notices/#terms'}>participation terms</a> and <a href={config.publicOrigin+'/notices/#privacy'}>privacy notice</a>.</span></label>
  {error&&<Notice error>{error}</Notice>}
  <div className="actions"><button type="button" className="btn blue" disabled={busy||!terms} onClick={()=>void run('register')}>{busy?'Opening passkey...':'Create volunteer account'}</button>
   <button type="button" className="btn outline" disabled={busy} onClick={()=>void run('authenticate')}>Sign in with passkey</button></div>
 </div>;
}
function Verify(){const{refresh}=useContext(Context);const[,navigate]=usePath();const[token]=useState(()=>{const value=new URLSearchParams(location.hash.slice(1)).get('token')||'';history.replaceState({},'',location.pathname);return value;});const[error,setError]=useState(''),[busy,setBusy]=useState(false);async function verify(){setBusy(true);try{await request('/api/auth/verify',{token});await refresh();navigate('/');}catch(e){setError((e as Error).message);}finally{setBusy(false);}}return <div className="narrow panel"><span className="eyebrow">WELCOME TO THE TEAM</span><h1>Confirm your sign-in.</h1><p>Continue only if you requested this email in this browser. Opening the email alone does not create a session.</p>{error&&<Notice error>{error}</Notice>}<button className="btn" onClick={verify} disabled={busy||!token}>{busy?'Confirming...':'Continue to my workspace'}</button><p className="fine">Links expire after 15 minutes and can be used once.</p><Link to="/join" className="textlink">Request a new link</Link></div>;}
const nav=[['/','Your first action'],['/materials','Materials library'],['/roles','Find your role'],['/orientation','First-hour orientation'],['/tasks','Available actions'],['/forms','Forms & practice'],['/activity','Activity status'],['/teams','Teams & events'],['/help','Help & corrections'],['/settings','Account settings']];
function Shell({children,path}:{children:React.ReactNode;path:string}){const{session,refresh,config}=useContext(Context);const[,navigate]=usePath();const[error,setError]=useState('');async function out(){try{await request('/api/auth/logout',{},session?.csrf);if(session?.account.id)await deleteProtectedLocalAccount(session.account.id);sessionStorage.removeItem('g28-bookmarks');await refresh();navigate('/join');}catch(e){setError((e as Error).message);}}return <div className="workspace"><aside><span className="eyebrow">VOLUNTEER WORKSPACE</span><nav aria-label="Volunteer navigation">{nav.map(([p,t])=><Link key={p} to={p} className={path===p?'active':''} aria-current={path===p?'page':undefined}>{t}</Link>)}{['owner','treasurer','auditor'].includes(session?.account.role||'')&&<Link to="/admin" className={path==='/admin'?'active':''}>Treasury administration</Link>}{['owner','auditor'].includes(session?.account.role||'')&&<Link to="/operations" className={path==='/operations'?'active':''}>Operations status</Link>}{config?.features.campaignEditor===true&&['owner','editor'].includes(session?.account.role||'')&&<a href="/editor/campaigns">Campaign content editor</a>}{['owner','auditor'].includes(session?.account.role||'')&&<Link to="/visitors" className={path==='/visitors'?'active':''}>Visitor analytics</Link>}{config?.features.staff&&session?.account.role!=='volunteer'&&<><Link to="/security">Staff security</Link><Link to="/activity-review">Activity review</Link><Link to="/assignments-admin">Assignments & training</Link></>}<Link to="/protected">Protected messages</Link></nav><div className="sidebar-note"><strong>Read. Learn. Act responsibly.</strong><p>Materials access is not authorization for restricted activities.</p></div><button className="text-button" onClick={out}>Sign out</button>{error&&<p role="alert">{error}</p>}</aside><div className="work-main">{children}</div></div>;}
function Home(){return <><span className="eyebrow">WELCOME TO THE TEAM</span><h1>Make your first<br/><em>move count.</em></h1><p className="lead">You do not need to do everything. Start with one action you can do well.</p><div className="first-action"><div><span className="eyebrow">YOUR FIRST HOUR</span><h2>A strong start,<br/>at your pace.</h2><p>Understand the principle. Choose a role. Practice one conversation.</p><Link className="btn" to="/orientation">Start orientation &rarr;</Link></div><ol><li><strong>Learn the principle</strong><p>Justice for All: protect rights, identify actual harm and repair it without creating another injustice.</p></li><li><strong>Choose a manageable role</strong><p>Match your time and interests to a useful first step.</p></li><li><strong>Use current materials</strong><p>Check the source, version and activity status before taking action.</p></li></ol></div><div className="cards two"><Link to="/materials" className="panel card-link"><h2>Your materials.</h2><p>Find approved guides in readable, searchable form.</p><span className="textlink">Open the library &rarr;</span></Link><Link to="/forms/action-card" className="panel card-link"><h2>Practice first.</h2><p>Turn a good intention into a clear plan, without collecting anyone else's information.</p><span className="textlink">Make an action card &rarr;</span></Link></div><Notice>No petitioning or other regulated activity is active without its exact current approval. Training does not substitute for authorization.</Notice></>;}
function Roles(){
 const {session}=useContext(Context);
 const[interest,setInterest]=useState(()=>{const requested=new URLSearchParams(location.search).get('role');return roleDefinitions.some(r=>r.id===requested)?requested!:'network';});
 const[minutes,setMinutes]=useState(30);
 const[training,setTraining]=useState(true);
 const[saveMessage,setSaveMessage]=useState('');
 const[error,setError]=useState('');
 const[saving,setSaving]=useState(false);
 useEffect(()=>{
  if(!session)return;
  let cancelled=false;
  request<{preferences:{roleId:string;minutes:number;willingToTrain:boolean}|null}>('/api/account/role-preferences')
   .then(result=>{
    if(cancelled||!result.preferences)return;
    const p=result.preferences;
    if(roleDefinitions.some(r=>r.id===p.roleId))setInterest(p.roleId);
    if([15,30,120,240].includes(p.minutes))setMinutes(p.minutes);
    setTraining(p.willingToTrain);
   })
   .catch(err=>{if(!cancelled)setError((err as Error).message);});
  return()=>{cancelled=true;};
 },[session?.account.id]);
 const recommendation=recommendRole({interest,minutes,willingToTrain:training});
 async function save(){
  if(!session)return;
  setSaving(true);setError('');setSaveMessage('');
  try{
   await request('/api/account/role-preferences',{roleId:interest,minutes,willingToTrain:training},session.csrf);
   setSaveMessage('Your volunteer role preferences were saved to your account. This does not authorize restricted activities.');
  }catch(e){setError((e as Error).message);}
  finally{setSaving(false);}
 }
 return <>
  <span className="eyebrow">TWELVE WAYS TO HELP</span>
  <h1>Find your place.</h1>
  <p className="lead">Use your interests and available time, not a political profile, to choose your first step.</p>
  <section className="chooser">
   <div>
    <label>What would you enjoy?
     <select value={interest} onChange={e=>{setInterest(e.target.value);setSaveMessage('');}}>
      {roleDefinitions.map(r=><option value={r.id} key={r.id}>{r.title}</option>)}
     </select>
    </label>
    <label>Time for a first action
     <select value={minutes} onChange={e=>{setMinutes(Number(e.target.value));setSaveMessage('');}}>
      <option value={15}>15 minutes</option><option value={30}>30 minutes</option>
      <option value={120}>1-2 hours</option><option value={240}>Half a day</option>
     </select>
    </label>
    <label className="check"><input type="checkbox" checked={training} onChange={e=>{setTraining(e.target.checked);setSaveMessage('');}}/><span>I am willing to complete training.</span></label>
    {session&&<button className="btn blue" type="button" disabled={saving} onClick={save}>{saving?'Saving...':'Save role preference'}</button>}
    {saveMessage&&<Notice>{saveMessage}</Notice>}
    {error&&<Notice error>{error}</Notice>}
   </div>
   <div className="recommendation" aria-live="polite">
    <span className="eyebrow">A POSSIBLE FIRST ROLE</span>
    <h2>{recommendation.role.title}</h2><p>{recommendation.reason}</p>
    <p>{recommendation.firstStep}</p>
    {recommendation.role.restricted&&<strong>Authorization required before the activity.</strong>}
   </div>
  </section>
  <div className="cards two">{roleDefinitions.map(r=><article key={r.id} className="panel role-card">
   <Link to={'/roles/'+r.id} className="role-card-link">
    <span className="eyebrow">{r.time}</span><h2>{r.title}</h2><p>{r.description}</p>
    {r.restricted?<span className="status-tag">Current approval required</span>:<span className="status-tag">Self-directed first steps</span>}
    <span className="role-card-cta">View role and next steps &rarr;</span>
   </Link>
  </article>)}</div>
 </>;
}
function RoleDetail({id}:{id:string}){
 const {session,config}=useContext(Context);
 const role=roleDefinitions.find(r=>r.id===id);
 if(!role)return <section className="role-detail"><h1>Role not found.</h1><p>That volunteer role is not in the current directory.</p><Link to="/roles" className="textlink">Return to all twelve roles &rarr;</Link></section>;
 return <section className="role-detail">
  <Link to={'/roles?role='+role.id} className="textlink">&larr; All twelve roles</Link>
  <span className="eyebrow spaced">VOLUNTEER ROLE / {role.time}</span>
  <h1>{role.title}</h1><p className="lead">{role.description}</p>
  <div className="panel spaced">
   <h2>Your next step</h2>
   {role.restricted?
    <><p>This role requires current, activity-specific authorization before any regulated work. Start with orientation and approved guidance; do not begin an inactive assignment.</p><p className="fine">Training, a role preference, or joining the campaign does not itself grant field authorization.</p></>:
    <><p>Start with the current orientation and reviewed materials, then choose a manageable action that fits your time and skills.</p><p className="fine">Use approved sources, protect other people's personal information, and stop when an activity requires additional permission.</p></>}
  </div>
  <div className="actions" aria-label="Next steps for this role">
   {session?<><Link to="/orientation" className="btn blue">Start orientation &rarr;</Link><Link to="/materials" className="btn outline">Read approved guides &rarr;</Link><Link to="/tasks" className="btn outline">View available actions &rarr;</Link>{role.restricted&&<Link to="/activity" className="btn outline">Check activity status &rarr;</Link>}</>:
    <><Link to="/join" className="btn blue">Join the team &rarr;</Link><a className="btn outline" href={(config?.publicOrigin||'')+'/issues/'}>Explore the issues &rarr;</a></>}
  </div>
 </section>;
}
function Materials(){
 const [q,setQ]=useState(''),[category,setCategory]=useState('all'),[query,setQuery]=useState('');
 const [savedOnly,setSavedOnly]=useState(false);
 useEffect(()=>{const t=setTimeout(()=>setQuery(q),200);return()=>clearTimeout(t);},[q]);
 const {data,error,loading}=useLoad<{materials:Material[];notice:string|null}>(`/api/materials?q=${encodeURIComponent(query)}&category=${encodeURIComponent(category)}`);
 const {data:bookmarks,error:bookmarkError,loading:bookmarkLoading}=useLoad<{materialIds:string[]}>('/api/account/bookmarks');
 const savedIds=new Set(bookmarks?.materialIds||[]);
 const visible=(data?.materials||[]).filter(material=>!savedOnly||savedIds.has(material.id));
 return <>
  <span className="eyebrow">CURRENT GUIDANCE, IN ONE PLACE</span>
  <h1>Your materials.</h1>
  <p className="lead">Search approved guides. Read online, download or return to guides saved to your volunteer account.</p>
  <div className="search-controls">
   <label>Search the library
    <input type="search" value={q} onChange={e=>setQ(e.target.value)} placeholder="Search by topic, role or phrase"/>
   </label>
   <label>Category
    <select value={category} onChange={e=>setCategory(e.target.value)}>
     {[['all','All materials'],['start','Start here'],['role','Role playbooks'],['policy','Policy kits'],['tools','Forms & training']].map(([v,t])=><option key={v} value={v}>{t}</option>)}
    </select>
   </label>
  </div>
  <label className="check">
   <input type="checkbox" checked={savedOnly} onChange={e=>setSavedOnly(e.target.checked)} disabled={bookmarkLoading}/>
   <span>Saved guides only{!bookmarkLoading&&!bookmarkError&&` (${savedIds.size})`}</span>
  </label>
  {loading&&<Notice>Searching current materials...</Notice>}
  {bookmarkLoading&&savedOnly&&<Notice>Loading your saved guides...</Notice>}
  {error&&<Notice error>{error}</Notice>}
  {bookmarkError&&<Notice error>Your saved guides could not be loaded. Try refreshing the page.</Notice>}
  {data?.notice&&<Notice>{data.notice}</Notice>}
  {savedOnly&&!bookmarkLoading&&!bookmarkError&&!loading&&!error&&!data?.notice&&visible.length===0&&
   <Notice>No saved current guides match these filters. Open a guide and select "Bookmark to my account" to add it here.</Notice>}
  <div className="cards two">
   {visible.map(m=><Link to={'/materials/'+m.id} className="panel card-link" key={m.id}>
    <span className="eyebrow">{m.category} / VERSION {m.revision}{savedIds.has(m.id)?' / SAVED':''}</span>
    <h2>{m.title}</h2><p>{m.description}</p>
    <span className="textlink">Read the guide &rarr;</span>
   </Link>)}
  </div>
 </>;
}
type DocBlock={type:string;level?:number;id?:string;text?:string;items?:string[];headers?:string[];rows?:string[][]};
type DocHeading={id:string;level:number;text:string};
type InlinePart={type:'text'|'link';text:string;url?:string;external?:boolean};
function MaterialInline({text}:{text:string}){
 const{config}=useContext(Context);
 return <>{(materialLinks(text) as InlinePart[]).map((part,i)=>{
  if(part.type==='text')return <React.Fragment key={i}>{part.text}</React.Fragment>;
  const href=part.url?.startsWith('/issues/')?(config?.publicOrigin||'')+part.url:part.url||'#';
  return <a key={i} href={href} target={part.external?'_blank':undefined} rel={part.external?'noopener noreferrer':undefined}>{part.text}</a>;
 })}</>;
}
function PlainDocument({text}:{text:string}){
 const {blocks,headings}=parseMaterialMarkdown(text) as {blocks:DocBlock[];headings:DocHeading[]};
 return <div className="document-layout">
 {headings.length>1&&<nav className="document-outline" aria-label="On this page">
   <h2>On this page</h2>
   <ol>{headings.map(h=><li key={h.id} className={'level-'+h.level}><a href={'#'+h.id}>{h.text}</a></li>)}</ol>
  </nav>}
 <div className="document-content">
 {blocks.map((block,i)=>{
  const t=block.text||'';
  if(block.type==='heading'){
    if(block.level===1)return <h2 id={block.id} key={i}><MaterialInline text={t}/></h2>;
    if(block.level===2)return <h3 id={block.id} key={i}><MaterialInline text={t}/></h3>;
    return <h4 id={block.id} key={i}><MaterialInline text={t}/></h4>;
  }
  if(block.type==='ul')return <ul key={i}>{block.items?.map((item,j)=><li key={j}><MaterialInline text={item}/></li>)}</ul>;
  if(block.type==='ol')return <ol key={i}>{block.items?.map((item,j)=><li key={j}><MaterialInline text={item}/></li>)}</ol>;
  if(block.type==='quote')return <blockquote key={i}><MaterialInline text={t}/></blockquote>;
  if(block.type==='code')return <pre key={i}><code>{t}</code></pre>;
  if(block.type==='rule')return <hr key={i}/>;
  if(block.type==='table')return <div className="document-table-wrap" role="region" tabIndex={0} aria-label="Document table" key={i}><table><thead><tr>{block.headers?.map((head,j)=><th scope="col" key={j}><MaterialInline text={head}/></th>)}</tr></thead><tbody>{block.rows?.map((row,j)=><tr key={j}>{row.map((cell,k)=><td key={k}><MaterialInline text={cell}/></td>)}</tr>)}</tbody></table></div>;
  return <p key={i}><MaterialInline text={t}/></p>;
 })}
 </div></div>;
}
function Document({id}:{id:string}){
 const{session}=useContext(Context);
 const{data,error,loading}=useLoad<Material>('/api/materials/'+encodeURIComponent(id));
 const[saved,setSaved]=useState(false);
 const[bookmarkSaving,setBookmarkSaving]=useState(false);
 const[reading,setReading]=useState<boolean|null>(null);
 const[saving,setSaving]=useState(false);
 const[saveError,setSaveError]=useState('');
 useEffect(()=>{
  let cancelled=false;
  setSaved(false);setReading(null);setSaveError('');
  request<{materialIds:string[]}>('/api/account/bookmarks')
   .then(result=>{if(!cancelled)setSaved(result.materialIds.includes(id));})
   .catch(e=>{if(!cancelled)setSaveError((e as Error).message);});
  return()=>{cancelled=true;};
 },[id,session?.account.id]);
 async function bookmark(){
  if(bookmarkSaving||!data)return;
  setSaveError('');setBookmarkSaving(true);
  try{
   const result=await request<{saved:boolean}>('/api/materials/'+encodeURIComponent(id)+'/bookmark',
    {saved:!saved},session?.csrf);
   setSaved(result.saved);
  }catch(e){setSaveError((e as Error).message);}
  finally{setBookmarkSaving(false);}
 }
 const isRead=reading??Boolean(data?.acknowledged);
 async function toggleReading(){
  if(!data||saving)return;
  setSaveError('');setSaving(true);
  try{
   const result=await request<{acknowledged:boolean}>('/api/materials/'+encodeURIComponent(id)+'/reading',{revision:data.revision,acknowledged:!isRead},session?.csrf);
   setReading(result.acknowledged);
  }catch(e){setSaveError((e as Error).message);}finally{setSaving(false);}
 }
 return <><Link to="/materials" className="textlink">&larr; Materials library</Link>
  {loading&&<Notice>Loading guide...</Notice>}{error&&<Notice error>{error}</Notice>}
  {data&&<><span className="eyebrow spaced">CURRENT GUIDE / VERSION {data.revision}</span><h1>{data.title}</h1>
   <div className="actions"><a className="btn" href={'/api/materials/'+encodeURIComponent(id)+'/download'}>Download Markdown</a>
   <button className="btn outline" aria-pressed={saved} disabled={bookmarkSaving} onClick={bookmark}>{bookmarkSaving?'Saving...':saved?'Saved to my account':'Bookmark to my account'}</button>
   <button className="btn outline" type="button" aria-pressed={isRead} disabled={saving} onClick={toggleReading}>{saving?'Saving...':isRead?'Read this version - undo':'I have read this version'}</button></div>
   {saveError&&<Notice error>{saveError}</Notice>}
   <p className="fine" aria-live="polite">{isRead?'Reading acknowledgment saved to your private account. You can undo it.':'You have not yet acknowledged reading this exact approved version.'}</p>
   <p className="fine">Bookmarks are saved to your volunteer account and follow you across signed-in devices. {data.readingNotice||'Reading a guide is not training certification or authorization for regulated campaign activity.'}</p>
   <PlainDocument text={data.body||''}/>
  </>}</>;
}
function Forms({id}:{id?:string}){const form=(worksheetTemplates as FormSpec[]).find(f=>f.id===id);const[values,setValues]=useState<Record<string,string>>({});useEffect(()=>setValues({}),[id]);if(!id)return <><span className="eyebrow">PLAN. PRACTICE. PREPARE.</span><h1>Put it into words.</h1><p className="lead">Twelve practical worksheets, readable and usable without a giant PDF.</p><Notice>Drafts stay in this tab. Nothing you type in a worksheet is submitted to the campaign.</Notice><div className="cards two">{(worksheetTemplates as FormSpec[]).map(f=><Link to={'/forms/'+f.id} className="panel card-link" key={f.id}><h2>{f.title}</h2><p>{f.restricted?'Planning and training only. Does not authorize an activity.':'A practical tool for a self-directed first step.'}</p><span className="textlink">Open worksheet &rarr;</span></Link>)}</div></>;if(!form)return <Notice error>This worksheet was not found.</Notice>;function download(){const blob=new Blob([worksheet(form!.id,values)],{type:'text/plain;charset=utf-8'});const url=URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download=form!.id+'-planning.md';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}return <><Link to="/forms" className="textlink">&larr; All worksheets</Link><span className="eyebrow spaced">PLANNING / PRACTICE ONLY</span><h1>{form.title}</h1><Notice>{form.notice}</Notice><div className="panel worksheet">{form.fields.map(f=><label key={f.name}>{f.label}{f.type==='textarea'?<textarea rows={4} maxLength={10000} value={values[f.name]||''} onChange={e=>setValues({...values,[f.name]:e.target.value})}/>:<input type={f.type} maxLength={1000} value={values[f.name]||''} onChange={e=>setValues({...values,[f.name]:e.target.value})}/>}</label>)}<div className="actions"><button className="btn" onClick={download}>Download my worksheet</button><button className="btn outline" onClick={()=>window.print()}>Print</button><button className="text-button" onClick={()=>setValues({})}>Clear this draft</button></div></div></>;}
function Tasks(){
 const{config,session}=useContext(Context);
 const{data,error}=useLoad<{tasks:{id:string;title:string;description:string;url:string;restricted:boolean;completed:boolean;decision:{allowed:boolean;reason:string}}[];tracking:string;completed:number;total:number}>('/api/tasks');
 const[changes,setChanges]=useState<Record<string,boolean>>({}),[pending,setPending]=useState<string|null>(null),[actionError,setActionError]=useState('');
 async function toggle(id:string,completed:boolean){
  setActionError('');setPending(id);
  try{await request('/api/tasks/'+encodeURIComponent(id)+'/completion',{completed:!completed},session?.csrf);setChanges(prev=>({...prev,[id]:!completed}));}
  catch(e){setActionError((e as Error).message);}finally{setPending(null);}
 }
 const completed=data?.tasks.filter(t=>!t.restricted&&(changes[t.id]??t.completed)).length||0;
 return <><span className="eyebrow">ONE GOOD STEP</span><h1>Choose your action.</h1>
 {config?.features.operationalTasks&&session&&<TaskBoard csrf={session.csrf} accountId={session.account.id}/>}
 <p className="lead">Choose a manageable first step, and keep a private checklist. Marking an action complete is your own reminder, never verified campaign work or permission for regulated outreach.</p>
 {data&&<p className="fine" aria-live="polite">Your first steps: {completed} of {data.total} marked complete. You can change these at any time.</p>}
 {error&&<Notice error>{error}</Notice>}{actionError&&<Notice error>{actionError}</Notice>}
 <div className="cards two">{data?.tasks.map(t=>{
 const done=changes[t.id]??t.completed;
 return <article className="panel" key={t.id}><h2>{t.title}</h2><p>{t.description}</p><p className="fine">{t.decision.reason}</p>
 {t.decision.allowed?<><div className="actions">{t.url==='/issues/'?<a className="btn blue" href={(config?.publicOrigin||'')+t.url}>Explore the issues</a>:<Link className="btn blue" to={t.url}>Get started &rarr;</Link>}
 <button className="btn outline" aria-pressed={done} disabled={pending!==null} onClick={()=>toggle(t.id,done)}>{pending===t.id?'Saving...':done?'Completed - undo':'Mark complete'}</button></div>{done&&<p className="fine" role="status">Saved on your private volunteer checklist.</p>}</>:<span className="status-tag">Activity not active</span>}
 </article>;})}</div></>;
}
type ActivitySummary={id:string;jurisdiction:string;election:string;activity:string;revision:number;validUntil:string;publishedCurrent:boolean;reason:string;requiredTrainingCount:number;activityAuthorized:false};
function Activity(){const{data,error}=useLoad<{notice:string;modules:ActivitySummary[]}>('/api/activity-status');return <><span className="eyebrow">KNOW WHAT IS AUTHORIZED</span><h1>Readiness matters.</h1>{error&&<Notice error>{error}</Notice>}<Notice>{data?.notice||'Checking current activity status...'}</Notice>
 {data?.modules?.length?<section className="cards two" aria-label="Published activity requirements">{data.modules.map(m=><article key={m.id} className="panel"><span className="eyebrow">{m.jurisdiction} · {m.election}</span><h2>{m.activity}</h2><p className="fine">Published revision {m.revision} · through {new Date(m.validUntil).toLocaleDateString()}</p><p><strong>{m.publishedCurrent?'Current published requirements':'Not currently available'}</strong></p><p>{m.reason}</p><p className="fine">Required training items: {m.requiredTrainingCount}. This does not verify your own completion or approve fieldwork.</p></article>)}</section>:null}
 <div className="panel spaced"><h2>Before a restricted activity</h2><p>Check the exact jurisdiction, election, activity, approved tool, required training, review dates and authorization. An old guide or a completed lesson is not sufficient.</p><p>Every actual regulated action requires two distinct verifiers, campaign publication approval for the exact revision, and all personal prerequisites. This read-only list does not activate tasks.</p><Link to="/roles" className="textlink">Review the roles &rarr;</Link></div></>;}
function PasskeySettings({csrf}:{csrf:string}){
 const{config}=useContext(Context);
 const[credentials,setCredentials]=useState<{id:string;createdAt:string|null}[]|null>(null);
 const[busy,setBusy]=useState(false),[error,setError]=useState(''),[message,setMessage]=useState('');
 async function load(){
  try{const r=await request<{credentials:{id:string;createdAt:string|null}[]}>('/api/passkeys');setCredentials(r.credentials);}
  catch(e){setError((e as Error).message);}
 }
 useEffect(()=>{if(config?.passkeyEnabled)void load();},[config?.passkeyEnabled]);
 if(!config?.passkeyEnabled)return null;
 async function add(){setBusy(true);setError('');setMessage('');try{
  if(!window.PublicKeyCredential)throw Error('Passkeys are not supported in this browser.');
  const r=await request<{options:Parameters<typeof startRegistration>[0]['optionsJSON']}>('/api/passkeys/add/options',{},csrf);
  const response=await startRegistration({optionsJSON:r.options});
  await request('/api/passkeys/add/verify',{response},csrf);
  await load();setMessage('Another passkey is now registered on this account.');
 }catch(e){setError((e as Error).message);}finally{setBusy(false);}}
 async function revoke(id:string){
  if(!window.confirm('Remove this passkey and sign out any other sessions? Make sure another passkey is available first.'))return;
  setBusy(true);setError('');setMessage('');
  try{await request('/api/passkeys/revoke',{id},csrf);await load();setMessage('Passkey removed and other sessions signed out.');}
  catch(e){setError((e as Error).message);}finally{setBusy(false);}
 }
 return <div className="panel spaced"><h2>Passkey access and backup</h2>
  <p>{credentials===null?'Checking account passkeys...':credentials.length+' passkey'+(credentials.length===1?'':'s')+' registered.'} Add a passkey on another trusted device or synchronized through a provider you control. Account recovery without an available passkey is not supported yet.</p>
  {error&&<Notice error>{error}</Notice>}{message&&<Notice>{message}</Notice>}
  <button type="button" className="btn blue" disabled={busy||credentials===null||credentials.length>=8} onClick={()=>void add()}>{busy?'Working...':'Add another passkey'}</button>
  {credentials&&<ul className="passkey-list">{credentials.map((item,index)=><li key={item.id}>
   <strong>Passkey {index+1}</strong> <span className="fine">{item.createdAt?'Added '+new Date(item.createdAt).toLocaleDateString():'Registered on this account'}</span>
   <button type="button" className="text-button" disabled={busy||credentials.length===1} aria-label={'Remove passkey '+(index+1)} onClick={()=>void revoke(item.id)}>Remove</button>
  </li>)}</ul>}
  {credentials?.length===1&&<p className="fine">Your only enrolled passkey cannot be removed. Register a backup first.</p>}
 </div>;
}
function Settings(){
 const{session,refresh}=useContext(Context);
 const[marketing,setMarketing]=useState(Boolean(session?.account.marketing));
 const[message,setMessage]=useState('');
 const[error,setError]=useState('');
 const[confirm,setConfirm]=useState('');
 const[exportBusy,setExportBusy]=useState(false);
 const[signoutBusy,setSignoutBusy]=useState(false);
 const[,navigate]=usePath();
 async function save(){
  setError('');setMessage('');
  try{await request('/api/account/consent',{marketing},session?.csrf);await refresh();setMessage('Your preference has been saved.');}
  catch(e){setError((e as Error).message);}
 }
 async function downloadExport(){
  setError('');setMessage('');setExportBusy(true);
  try{
   const data=await request<Record<string,unknown>>('/api/account/export');
   const blob=new Blob([JSON.stringify(data,null,2)+'\n'],{type:'application/json;charset=utf-8'});
   const uri=URL.createObjectURL(blob);
   const anchor=document.createElement('a');
   anchor.href=uri;anchor.download='galinsky-volunteer-account.json';
   document.body.appendChild(anchor);anchor.click();anchor.remove();
   setTimeout(()=>URL.revokeObjectURL(uri),1000);
   setMessage('Your account activity export was downloaded directly to your device.');
  }catch(e){setError((e as Error).message);}
  finally{setExportBusy(false);}
 }
 async function signOutEverywhere(){
  setError('');setMessage('');setSignoutBusy(true);
  try{
   await request('/api/account/revoke-sessions',{confirm:'sign out everywhere'},session?.csrf);
   if(session?.account.id)await deleteProtectedLocalAccount(session.account.id);sessionStorage.removeItem('g28-bookmarks');await refresh();navigate('/join');
  }catch(e){setError((e as Error).message);}
  finally{setSignoutBusy(false);}
 }
 async function close(){
  setError('');setMessage('');
  try{
   await request('/api/account/close',{confirm},session?.csrf);
   if(session?.account.id)await deleteProtectedLocalAccount(session.account.id);sessionStorage.removeItem('g28-bookmarks');await refresh();navigate('/join');
  }catch(e){setError((e as Error).message);}
 }
 return <>
  <span className="eyebrow">YOUR ACCOUNT, YOUR CHOICES</span><h1>Account settings.</h1>
  {message&&<Notice>{message}</Notice>}{error&&<Notice error>{error}</Notice>}
  {session&&<PasskeySettings csrf={session.csrf}/>}
  <div className="panel">
   <h2>Email preferences</h2>
   <label className="check"><input type="checkbox" checked={marketing} onChange={e=>setMarketing(e.target.checked)}/><span>Receive optional campaign updates. Account and security messages remain separate.</span></label>
   <button className="btn" onClick={save}>Save preference</button>
  </div>
  <div className="panel spaced">
   <h2>Download my account activity</h2>
   <p>Export your volunteer role choices, checklist progress, reviewed-material acknowledgments and account consent as a JSON file. Your download stays on your device. No private tokens or other volunteers' information is included.</p>
   <button className="btn outline" disabled={exportBusy} onClick={downloadExport}>{exportBusy?'Preparing export...':'Download my account data'}</button>
  </div>
  <div className="panel spaced">
   <h2>Sign out of all devices</h2>
   <p>Immediately revoke every active volunteer session, including this one. Signing in again will require a new verified email link.</p>
   <button className="btn outline" disabled={signoutBusy} onClick={signOutEverywhere}>{signoutBusy?'Signing out...':'Sign out everywhere'}</button>
  </div>
  <div className="panel spaced">
   <h2>Close this volunteer account</h2>
   <p>Closing the account revokes its sessions and deletes its account access records. This does not erase any separately required campaign finance records.</p>
   <label>Type “close my account” to confirm<input value={confirm} onChange={e=>setConfirm(e.target.value)}/></label>
   <button className="btn outline" onClick={close} disabled={confirm!=='close my account'}>Close my account</button>
  </div>
 </>;
}
function App(){const[path]=usePath();const[config,setConfig]=useState<Config|null>(null),[session,setSession]=useState<Session|null>(null),[ready,setReady]=useState(false),[error,setError]=useState('');async function refresh(){try{setSession(await request<Session>('/api/session'));}catch(e){if(e instanceof ApiError&&e.status===401)setSession(null);else throw e;}}useEffect(()=>{Promise.all([request<Config>('/api/config').then(setConfig),refresh()]).catch(e=>setError(e.message)).finally(()=>setReady(true));},[]);useEffect(()=>{
  const label=path==='/join'?'Join the team':path==='/verify'?'Verify sign-in':path.startsWith('/roles/')?'Volunteer role details':path.startsWith('/materials/')?'Read a volunteer guide':(path==='/operations'?'Operations status':path==='/visitors'?'Visitor analytics':nav.find(([route])=>route===path)?.[1])||'Volunteer workspace';
  document.title=label+' | Galinsky 2028';
  document.getElementById('main')?.focus({preventScroll:true});
 },[path]);let page:React.ReactNode;
 if(!ready)page=<div className="narrow"><Notice>Opening your workspace...</Notice></div>;
 else if(error)page=<div className="narrow"><Notice error>{error}</Notice><button className="btn" onClick={()=>location.reload()}>Try again</button></div>;
 else if(path==='/verify')page=<Verify/>;
 else if(path==='/roles'&&!session)page=<div className="public-roles"><Roles/><Link className="btn" to="/join">Join the team &rarr;</Link></div>;
 else if(path.startsWith('/roles/')&&!session)page=<div className="public-roles"><RoleDetail id={path.split('/')[2]||''}/></div>;
 else if(!session)page=<Join/>;
 else {const parts=path.split('/').filter(Boolean);page=<Shell path={path}>{parts[0]==='materials'?(parts[1]?<Document id={parts[1]}/>:<Materials/>):parts[0]==='forms'?<Forms id={parts[1]}/>:parts[0]==='roles'&&parts[1]?<RoleDetail id={parts[1]}/>:path==='/roles'?<Roles/>:path==='/orientation'?<Orientation csrf={session.csrf}/>:path==='/tasks'?<Tasks/>:path==='/activity'?<Activity/>:path==='/teams'?<Coordination csrf={session.csrf} owner={session.account.role==='owner'} enabled={config?.features.coordination===true}/>:path==='/assignments-admin'?<OperationsAdmin csrf={session.csrf} role={session.account.role}/>:path==='/activity-review'?<ActivityReview csrf={session.csrf}/>:path==='/security'?<StaffSecurity csrf={session.csrf}/>:path==='/settings'?<Settings/>:path==='/operations'?<AdminOperations role={session.account.role}/>:path==='/protected'?<React.Suspense fallback={<p role="status">Loading protected messages…</p>}><ProtectedReports csrf={session.csrf} accountId={session.account.id} role={session.account.role} enabled={config?.features.protectedSubmissions===true||config?.features.protectedSetup===true} intakeEnabled={config?.features.protectedSubmissions===true}/></React.Suspense>:path==='/help'?<HelpCenter csrf={session.csrf} role={session.account.role} enabled={config?.features.helpRequests===true}/>:path==='/visitors'?<AdminVisitors role={session.account.role}/>:path==='/admin'?<AdminTreasury role={session.account.role} csrf={session.csrf}/>:<Home/>}</Shell>;}
 return <Context.Provider value={{config,session,refresh}}><a className="skip" href="#main">Skip to main content</a><div className="topline">JUSTICE FOR ALL &bull; PHILLIP GALINSKY 2028</div><header><div className="header-inner"><Brand/><div className="header-links"><a href={(config?.publicOrigin||'')+'/issues/'}>The issues</a><Link to="/roles">Find your role</Link>{session&&<Link to="/settings">My account</Link>}</div></div></header><div className="route-announcer" role="status" aria-live="polite" aria-atomic="true">{path==='/join'?'Join the team':path==='/verify'?'Confirm sign-in':(path==='/operations'?'Operations status':nav.find(([route])=>route===path)?.[1])||'Volunteer workspace'}</div><main id="main" tabIndex={-1}>{page}</main><footer><strong>Justice for All.</strong><span>Phillip Galinsky for America 2028.</span><a href={(config?.publicOrigin||'')+'/notices/#privacy'}>Privacy &amp; accessibility</a></footer></Context.Provider>;
}
createRoot(document.getElementById('root')!).render(<App/>);
