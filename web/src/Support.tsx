import {useState, type FormEvent} from 'react';

/** Public support intake; all business references are supplied by the customer. */
export function Support(){
 const [channel,setChannel]=useState(new URLSearchParams(window.location.search).get('channel')??'');
 const [order,setOrder]=useState('');const [text,setText]=useState('');
 const [busy,setBusy]=useState(false);const [message,setMessage]=useState('');
 async function submit(event:FormEvent){
  event.preventDefault();setBusy(true);setMessage('');
  try{
   const response=await fetch('/public/tickets',{method:'POST',credentials:'omit',headers:{'Content-Type':'application/json'},body:JSON.stringify({channel_id:channel,order_id:order||null,text})});
   const result=await response.json();
   if(!response.ok)throw new Error(String(result.reason));
   setMessage('Ticket received. Reference: '+String(result.ticket_id));setText('');
  }catch(error){setMessage(error instanceof Error?error.message:'Unable to submit ticket');}finally{setBusy(false);}
 }
 return <main><header><a className="brand" href="/">◈ IntentLock</a><span className="badge">SUPPORT</span></header><section className="intro"><h1>Contact support.</h1><p>Describe the issue for review. A support request does not authorize a refund. Please omit card numbers and identity documents.</p></section><form className="panel" onSubmit={event=>void submit(event)}><label>Support channel<input required maxLength={128} value={channel} onChange={event=>setChannel(event.target.value)}/></label><label>Order reference (optional)<input maxLength={128} value={order} onChange={event=>setOrder(event.target.value)}/></label><label>Your request<textarea required maxLength={16000} rows={9} value={text} onChange={event=>setText(event.target.value)}/></label><button disabled={busy||!channel||!text.trim()}>{busy?'Submitting…':'Submit support request'}</button><p role="status">{message}</p></form><footer>Customer content is reviewed as untrusted data. Automated assistance receives masked text.</footer></main>;
}
