import {TreasuryExport} from './TreasuryExport';
import {TreasuryWorkflow} from './TreasuryWorkflow';
import {STAFF_ROLES} from '../../../packages/core/staff-permissions.mjs';
import React,{useEffect,useState,FormEvent} from 'react';
import {request} from './api';
import './admin-treasury.css';

type TreasuryEntry={slot:string;maskedLabel:string;updatedAt:string};
type TreasuryStatus={mode:string;role:string;credentials:TreasuryEntry[];slots:string[];bankConfigured:boolean;vaultConfigured:boolean;notice:string};
type Grant={reference:string;role:string;label:string;createdAt:string};
const names:Record<string,string>={'merchant-a':'Processor 1','merchant-b':'Processor 2','merchant-c':'Processor 3','merchant-d':'Processor 4'};
function Feedback({error,message}:{error:string;message:string}){return <>{error&&<p className="admin-feedback error" role="alert">{error}</p>}{message&&<p className="admin-feedback" role="status">{message}</p>}</>;}
function BankSettings({csrf,saved,onSaved}:{csrf:string;saved?:TreasuryEntry;onSaved:()=>Promise<void>}){
 const[bankName,setBankName]=useState(''),[accountName,setAccountName]=useState(''),[routing,setRouting]=useState(''),[account,setAccount]=useState('');
 const[busy,setBusy]=useState(false),[error,setError]=useState(''),[message,setMessage]=useState('');
 async function submit(e:FormEvent){e.preventDefault();setError('');setMessage('');setBusy(true);try{
  await request('/api/admin/settings/bank',{bankName,accountName,routingNumber:routing,accountNumber:account},csrf);
  setAccount('');setRouting('');setMessage('Bank details encrypted and saved. No payment, verification deposit or transfer was initiated.');
  await onSaved();
 }catch(e){setError((e as Error).message);}finally{setBusy(false);}}
 return <section className="panel spaced"><h2>Committee settlement bank</h2>
  <p>The bank account is stored in the encrypted treasurer vault. No bank information is returned to the browser after saving.</p>
  <p className="admin-state">{saved?'Stored: '+saved.maskedLabel:'No bank account details stored.'}</p>
  <Feedback error={error} message={message}/>
  <form onSubmit={submit} autoComplete="off" className="admin-fields">
   <label>Bank name<input required maxLength={120} value={bankName} onChange={e=>setBankName(e.target.value)} autoComplete="off"/></label>
   <label>Legal account holder<input required maxLength={180} value={accountName} onChange={e=>setAccountName(e.target.value)} autoComplete="off"/></label>
   <label>ABA routing number<input required inputMode="numeric" pattern="[0-9]{9}" maxLength={9} value={routing} onChange={e=>setRouting(e.target.value)} type="password" autoComplete="off"/></label>
   <label>Account number<input required inputMode="numeric" maxLength={17} minLength={4} value={account} onChange={e=>setAccount(e.target.value)} type="password" autoComplete="off"/></label>
   <button disabled={busy||!routing||!account} className="btn">{busy?'Saving...':'Encrypt and save bank account'}</button>
  </form><p className="fine">A saved number is not confirmation the bank has verified the committee account. Processor-hosted bank onboarding may still be required.</p>
 </section>;
}
function MerchantSettings({slot,saved,csrf,onSaved}:{slot:string;saved?:TreasuryEntry;csrf:string;onSaved:()=>Promise<void>}){
 const[merchantId,setMerchantId]=useState(''),[apiKey,setApiKey]=useState(''),[webhookSecret,setWebhookSecret]=useState(''),[checkoutUrl,setCheckoutUrl]=useState('');
 const[busy,setBusy]=useState(false),[error,setError]=useState(''),[message,setMessage]=useState('');
 async function submit(e:FormEvent){e.preventDefault();setBusy(true);setError('');setMessage('');
  try{
   await request('/api/admin/settings/providers/'+slot,{mode:'sandbox',merchantId,apiKey,webhookSecret,checkoutUrl},csrf);
   setApiKey('');setWebhookSecret('');setMessage('Sandbox settings encrypted and saved. This does not activate live donations or verify a processor contract.');
   await onSaved();
  }catch(e){setError((e as Error).message);}finally{setBusy(false);}
 }
 return <section className="panel spaced"><h2>{names[slot]||slot} — sandbox credentials</h2>
  <p className="admin-state">{saved?'Stored: '+saved.maskedLabel:'No sandbox credentials stored.'}</p>
  <Feedback error={error} message={message}/>
  <form onSubmit={submit} className="admin-fields" autoComplete="off">
   <label>Sandbox merchant/account ID<input required maxLength={140} value={merchantId} onChange={e=>setMerchantId(e.target.value)} autoComplete="off"/></label>
   <label>Sandbox API key<input required type="password" autoComplete="off" maxLength={4096} value={apiKey} onChange={e=>setApiKey(e.target.value)}/></label>
   <label>Sandbox webhook signing secret (if supplied)<input type="password" maxLength={4096} autoComplete="off" value={webhookSecret} onChange={e=>setWebhookSecret(e.target.value)}/></label>
   <label>Sandbox checkout URL (optional)<input type="url" maxLength={2048} value={checkoutUrl} onChange={e=>setCheckoutUrl(e.target.value)} placeholder="https://sandbox.provider.example/checkout" autoComplete="off"/></label>
   <button className="btn" disabled={busy||!apiKey||!merchantId}>{busy?'Saving...':'Encrypt and save sandbox settings'}</button>
  </form>
 </section>;
}
function StaffInvitations({csrf}:{csrf:string}){
 const[email,setEmail]=useState(''),[role,setRole]=useState('auditor'),[label,setLabel]=useState('');
 const[grants,setGrants]=useState<Grant[]>([]),[busy,setBusy]=useState(false),[error,setError]=useState(''),[message,setMessage]=useState('');
 async function load(){const r=await request<{grants:Grant[]}>('/api/admin/grants');setGrants(r.grants);}
 useEffect(()=>{load().catch(e=>setError(e.message));},[]);
 async function submit(e:FormEvent){e.preventDefault();setBusy(true);setMessage('');setError('');try{
  await request('/api/admin/grants',{email,role,label},csrf);await load();setEmail('');setLabel('');
  setMessage('Invitation registered. Notify this person privately; they must verify control of the invited email address to sign in.');
 }catch(e){setError((e as Error).message);}finally{setBusy(false);}}
 async function revoke(reference:string){setError('');setMessage('');try{await request('/api/admin/grants/revoke',{reference},csrf);await load();setMessage('Staff authorization revoked. Existing sessions no longer have treasury privileges.');}catch(e){setError((e as Error).message);}}
 return <section className="panel spaced"><h2>Staff permissions</h2>
  <p>You are the sole initial administrator. Additional people receive individually revocable roles only after you invite them and they verify their own email. No shared admin password.</p>
  <Feedback error={error} message={message}/>
  <form onSubmit={submit} className="admin-fields">
   <label>Invited person's email<input required type="email" maxLength={254} autoComplete="off" value={email} onChange={e=>setEmail(e.target.value)}/></label>
   <label>Display label<input required maxLength={90} value={label} onChange={e=>setLabel(e.target.value)} placeholder="Treasury assistant" autoComplete="off"/></label>
   <label>Role<select value={role} onChange={e=>setRole(e.target.value)}>{STAFF_ROLES.map((r:string)=><option key={r} value={r}>{r.replaceAll('-',' ')}</option>)}</select></label>
   <button className="btn" disabled={busy}>{busy?'Inviting...':'Register invitation'}</button>
  </form>
  <h3>Active invitations</h3>
  {grants.length?<ul className="admin-grants">{grants.map(g=><li key={g.reference}><span><strong>{g.label}</strong><small>{g.role} · reference {g.reference}</small></span><button className="btn outline" onClick={()=>revoke(g.reference)}>Revoke</button></li>)}</ul>:<p>No additional staff are authorized.</p>}
  <p className="fine">Invited email addresses are HMAC-indexed; the administrator list exposes labels and short references, not mailbox addresses.</p>
 </section>;
}
export function AdminTreasury({role,csrf}:{role:string;csrf:string}){
 const[data,setData]=useState<TreasuryStatus|null>(null),[error,setError]=useState('');
 async function refresh(){setData(await request<TreasuryStatus>('/api/admin/settings'));}
 useEffect(()=>{refresh().catch(e=>setError(e.message));},[]);
 if(!['owner','treasurer','auditor'].includes(role))return <section className="narrow panel"><h1>Restricted administration.</h1><p>A volunteer login does not authorize banking or payment settings.</p></section>;
 return <div className="admin-treasury"><span className="eyebrow">PRIVATE CAMPAIGN TREASURY</span><h1>Financial settings.</h1>
  <p className="lead">Configure the committee bank account and four independent processor connections here. No credentials belong in GitHub, volunteer materials or chat.</p>
  {error&&<Feedback error={error} message=""/>}
  {data?<><div className="panel admin-status"><h2>Release controls</h2><p>Account role: <strong>{data.role}</strong>. <strong>Sandbox only.</strong> Four slots are reserved; no payment processor is approved for live donations.</p><p>{data.notice}</p></div>
    {role!=='auditor'&&<BankSettings saved={data.credentials.find(x=>x.slot==='bank')} csrf={csrf} onSaved={refresh}/>}
    <h2 className="admin-section-heading">Processor connections</h2>
    {data.slots.map(slot=>role==='auditor'?<div key={slot} className="panel spaced"><h3>{names[slot]}</h3><p>{data.credentials.find(x=>x.slot===slot)?.maskedLabel||'Not configured'}</p></div>:<MerchantSettings key={slot} slot={slot} csrf={csrf} saved={data.credentials.find(x=>x.slot===slot)} onSaved={refresh}/>)}
    {role!=='auditor'&&<TreasuryExport csrf={csrf}/>}
    {role!=='auditor'&&<TreasuryWorkflow csrf={csrf}/>}
    {role==='owner'&&<StaffInvitations csrf={csrf}/>}
   </>:!error?<p role="status">Checking treasury permissions...</p>:null}
 </div>;
}
