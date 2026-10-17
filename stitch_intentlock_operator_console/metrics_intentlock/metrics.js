/** Stitch Metrics: authenticated actual eval_runs only, no sample or fallback data. */
const element=id=>document.getElementById(id);
let cursor=null;
let busy=false;
let connected=false;
async function api(path,body){
 const response=await fetch('/v1/'+path,{method:body?'POST':'GET',credentials:'same-origin',headers:body?{'Content-Type':'application/json'}:{},body:body?JSON.stringify(body):undefined});
 if(!response.headers.get('content-type')?.includes('application/json'))throw new Error('GATEWAY_UNAVAILABLE');
 const data=await response.json();
 if(!response.ok)throw new Error(String(data.reason??'Request failed'));
 return data;
}
function textCell(row,value){const td=document.createElement('td');td.textContent=String(value);row.append(td);}
function measured(value){return typeof value==='number'?String(Math.round(value*1000)/1000):'unmeasured';}
async function load(next=false){
 if(busy)return;
 busy=true;element('refresh').disabled=true;
 try{
  const page=await api('eval-runs?limit=20'+(next&&cursor?'&cursor='+encodeURIComponent(cursor):''));
  element('runs').replaceChildren();
  for(const run of page.items){
   const row=document.createElement('tr');const s=run.summary;const timing=s.gateway_path_overhead_valid??{};
   textCell(row,new Date(run.started_at*1000).toISOString());textCell(row,run.git_sha??'unavailable');textCell(row,run.status+(s.kind==='READINESS'?' · readiness':''));
   textCell(row,`${s.misuse_passed??0} / ${s.misuse_attempted??0}`);textCell(row,`${s.valid_completed??0} / ${s.valid_attempted??0}`);
   textCell(row,[timing.p50_ms,timing.p95_ms,timing.p99_ms].map(measured).join(' / '));
   const cell=document.createElement('td');const button=document.createElement('button');button.textContent=s.kind==='READINESS'?'View prerequisites':'Inspect';
   button.addEventListener('click',async()=>{try{const detail=await api('eval-runs/'+encodeURIComponent(run.id));element('detail').textContent=JSON.stringify(detail,null,2);element('detail-panel').hidden=false;}catch(error){element('status').textContent=error.message;}});
   cell.append(button);row.append(cell);element('runs').append(row);
  }
  connected=true;element('connect').hidden=true;
  cursor=page.next_cursor;element('next').hidden=!cursor;element('empty').hidden=page.items.length>0;
  element('empty').textContent='No recorded runs on this page.';element('status').textContent='Loaded actual history for tenant '+page.tenant_id+'.';
 }catch(error){connected=false;element('connect').hidden=false;element('status').textContent=error.message;}finally{busy=false;element('refresh').disabled=false;}
}
element('connect').addEventListener('submit',async event=>{
 event.preventDefault();
 try{await api('session',{session_token:element('session').value,csrf_token:element('csrf').value});element('session').value='';element('csrf').value='';await load();}catch(error){element('status').textContent=error.message;}
});
element('refresh').addEventListener('click',()=>void load());element('next').addEventListener('click',()=>void load(true));

void load();
setInterval(()=>{if(connected&&!document.hidden)void load();},30000);
