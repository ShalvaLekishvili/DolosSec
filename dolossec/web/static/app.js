const $ = id => document.getElementById(id);
const S = {run:null, es:null, path:null, parent:null, cap:[], ai:null};
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const show = (id, on=true) => $(id).classList.toggle('hidden', !on);

async function api(url, opt={}) {
  const r = await fetch(url, {headers:{'Content-Type':'application/json', ...(opt.headers||{})}, ...opt});
  if (!r.ok) {
    let d = 'Request failed';
    try { const body = await r.json(); d = Array.isArray(body.detail) ? body.detail.map(x=>x.msg||String(x)).join('; ') : (body.detail || d); } catch {}
    throw Error(d);
  }
  return r.json();
}

document.querySelectorAll('[data-go]').forEach(b => b.onclick = () => $(b.dataset.go).scrollIntoView({behavior:'smooth'}));
document.querySelectorAll('.tab').forEach(b => b.onclick = () => {
  document.querySelectorAll('.tab').forEach(x => x.classList.toggle('active', x === b));
  $('target-type').value = b.dataset.type;
  show('local-wrap', b.dataset.type === 'local_path');
  show('url-wrap', b.dataset.type === 'url');
  show('adapter-wrap', b.dataset.type === 'local_path');
});

function renderAi(ai, health) {
  S.ai = ai;
  const o = ai.ollama || {};
  $('ollama-badge').textContent = o.reachable ? `Online · ${o.version || 'unknown'}` : 'Offline';
  $('ollama-badge').classList.toggle('ok', Boolean(o.reachable));
  $('ollama-endpoint').textContent = o.base_url || 'http://127.0.0.1:11434';
  const models = o.models || [];
  $('ollama-models').textContent = models.length ? models.map(x => x.name).join(', ') : 'No local models detected';

  const select = $('ai-model');
  select.innerHTML = '<option value="">Use configured model</option>' + models.map(x => `<option value="${esc(x.name)}">${esc(x.name)}${x.parameter_size ? ` · ${esc(x.parameter_size)}` : ''}</option>`).join('');
  const configured = ai.configured_model || health.model || '';
  if (configured && models.some(x => x.name === configured)) select.value = configured;

  $('planner-provider').value = ['ollama','openai','deterministic'].includes(ai.configured_provider) ? ai.configured_provider : 'default';
  if (o.reachable && models.length) {
    $('ai-hint').textContent = `Ollama ready. ${models.length} local model${models.length===1?'':'s'} available.`;
  } else if (o.reachable) {
    $('ai-hint').textContent = 'Ollama is running but has no local model. Run: ollama pull qwen3.5:9b';
  } else {
    $('ai-hint').textContent = 'Ollama is offline. Run: dolos ollama install-guide';
  }
}

async function boot() {
  const [h, c, ai] = await Promise.all([api('/api/health'), api('/api/capabilities'), api('/api/ai/status')]);
  $('engine').textContent = `Engine online · ${h.version}`;
  $('planner').textContent = `Default: ${h.planner}${h.model ? ' / '+h.model : ''}`;
  S.cap = c.adapters;
  renderAdapters(c.adapters);
  renderAi(ai, h);
  await history();
}

function renderAdapters(a) {
  $('adapters').innerHTML = a.filter(x=>x.id!=='nuclei').map(x=>`<label class="adapter"><input type="checkbox" value="${x.id}" ${(!x.installed||!x.enabled)?'disabled':''}><span><b>${esc(x.name)}</b><small>${esc(x.description)} · ${x.installed?'installed':'not installed'}${x.enabled?'':' · disabled by policy'}</small></span></label>`).join('') + a.filter(x=>x.id==='nuclei').map(x=>`<div class="adapter"><span><b>Nuclei</b><small>${esc(x.description)}</small></span></div>`).join('');
}

async function history() {
  const d = await api('/api/runs');
  $('history-list').innerHTML = d.runs.length ? d.runs.map(r=>`<div class="history-item" data-run="${r.run_id}"><b>${esc(r.target)}</b><small>${esc(r.run_id)} · ${esc(r.mode)} · ${esc(r.planner)}${r.planner_model?' / '+esc(r.planner_model):''} · ${esc(r.status)} · ${r.findings_count} findings</small></div>`).join('') : '<div class="empty">No prior scans.</div>';
  document.querySelectorAll('[data-run]').forEach(x=>x.onclick=()=>loadRun(x.dataset.run));
}
$('refresh-history').onclick = history;

function sev(counts={}) {$('severity').innerHTML=['critical','high','medium','low','info'].map(k=>`<div>${k.toUpperCase()}<b>${counts[k]||0}</b></div>`).join('');}
function agents(events=[]) {
  const names=['planner','source-researcher','web-researcher','reporter']; const last={};
  events.forEach(e=>{const a=e.data?.agent;if(a)last[a]=e});
  $('agents').innerHTML=names.map(n=>`<div class="agent ${last[n]?'active':''}"><b>${n}</b><br>${esc(last[n]?.message||'idle')}</div>`).join('');
}
function surface(data={}) {
  const pages=data.pages||[], forms=data.forms||[], scripts=data.scripts||[], api=data.api_hints||[], params=data.parameters||[], cookies=data.cookies||[], tech=data.technologies||[];
  $('surface-total').textContent=data.pages_crawled!=null?`${data.pages_crawled} pages mapped`:'Not mapped';
  $('surface-summary').innerHTML=[['Pages',data.pages_crawled||0],['Forms',forms.length],['Scripts',scripts.length],['API hints',api.length],['Parameters',params.length],['Cookies',cookies.length]].map(([k,v])=>`<div class="surface-stat"><small>${esc(k)}</small><b>${v}</b></div>`).join('');
  if(!data.pages_crawled){$('surface-details').innerHTML='<div class="empty">No web inventory for this run.</div>';return;}
  const pageRows=pages.slice(0,20).map(p=>`<li><code>${esc(p.status_code??'?')}</code> <code>${esc(p.url)}</code>${p.forms?` · ${p.forms} form${p.forms===1?'':'s'}`:''}</li>`).join('');
  const formRows=forms.slice(0,12).map(f=>`<li><code>${esc(f.method)}</code> <code>${esc(f.action)}</code>${f.has_password?' · password':''}${f.has_file_upload?' · file upload':''}</li>`).join('');
  $('surface-details').innerHTML=`<details open><summary>Discovered routes</summary><ul>${pageRows||'<li>None</li>'}</ul></details>${forms.length?`<details><summary>Forms</summary><ul>${formRows}</ul></details>`:''}${api.length?`<details><summary>API / service hints</summary><ul>${api.slice(0,20).map(x=>`<li><code>${esc(x)}</code></li>`).join('')}</ul></details>`:''}${tech.length?`<details><summary>Technology signals</summary><ul>${tech.slice(0,20).map(x=>`<li><code>${esc(x)}</code></li>`).join('')}</ul></details>`:''}`;
}
function findings(list=[]) {
  $('run-count').textContent=list.length; $('finding-total').textContent=`${list.length} findings`;
  $('finding-list').innerHTML=list.length?list.map(f=>`<article class="finding"><b>${esc(f.title)}</b><div class="meta"><span class="badge">${esc(f.severity)}</span><span class="badge">${esc(f.id)}</span><span class="badge">${esc(f.cwe||'CWE unmapped')}</span><span class="badge">CVSS ${f.cvss_score??'pending'}</span><span class="badge">${Math.round((f.confidence||0)*100)}% confidence</span></div><p>${esc(f.description)}</p><details><summary>Evidence & remediation</summary>${(f.evidence||[]).map(e=>`<pre>${esc(e)}</pre>`).join('')}<p><b>Remediation:</b> ${esc(f.remediation)}</p><p><b>Source:</b> ${esc(f.source_tool||'dolossec')}</p></details></article>`).join(''):'<div class="empty">No findings.</div>';
}
function timeline(events=[]) {
  $('timeline').innerHTML=events.length?events.slice(-100).map(e=>`<div class="event"><b>${esc(e.message)}</b><small>${esc(e.data?.agent||'system')} · ${esc(e.type)} · ${new Date(e.timestamp).toLocaleTimeString()}</small></div>`).join(''):'<div class="empty">No events.</div>';
  agents(events);
}
function renderRun(r) {
  S.run=r; $('run-id').textContent=r.run_id; $('run-target').textContent=r.target; $('run-mode').textContent=r.mode;
  $('run-ai').textContent=`${r.planner}${r.planner_model?' / '+r.planner_model:''}`;
  $('status').textContent=r.status; surface(r.surface||{}); findings(r.findings||[]); sev(r.severity_counts||{}); timeline(r.events||[]);
  $('report').textContent=r.report||r.error||'Report not ready.'; show('approve',r.status==='awaiting_approval');
  if(r.status==='completed') {show('downloads');$('dl-report').href=`/api/runs/${r.run_id}/download/report`;$('dl-json').href=`/api/runs/${r.run_id}/download/findings`;$('dl-audit').href=`/api/runs/${r.run_id}/download/audit`;$('dl-obs').href=`/api/runs/${r.run_id}/download/observations`;} else show('downloads',false);
}
async function loadRun(id) {const r=await api(`/api/runs/${id}`);renderRun(r);if(!['completed','failed','interrupted','awaiting_approval'].includes(r.status))stream(id);$('live').scrollIntoView({behavior:'smooth'});}
function stream(id) {if(S.es)S.es.close();const es=new EventSource(`/api/runs/${id}/events`);S.es=es;es.addEventListener('progress',async()=>renderRun(await api(`/api/runs/${id}`)));es.addEventListener('done',async()=>{es.close();renderRun(await api(`/api/runs/${id}`));history();});}
$('approve').onclick=async()=>{const analyst=prompt('Analyst name for approval audit record:');if(!analyst)return;const r=await api(`/api/runs/${S.run.run_id}/approve`,{method:'POST',body:JSON.stringify({analyst})});renderRun(r);stream(r.run_id);};

$('planner-provider').onchange = () => {
  const provider = $('planner-provider').value;
  $('ai-model').disabled = !['ollama','default'].includes(provider);
};

$('scan-form').onsubmit=async e=>{
  e.preventDefault(); show('form-error',false);
  const type=$('target-type').value, target=type==='local_path'?$('local-path').value.trim():$('target-url').value.trim();
  const provider=$('planner-provider').value, model=['ollama','default'].includes(provider) ? ($('ai-model').value || null) : null;
  const body={target_type:type,target,mode:$('mode').value,allow_private_networks:$('allow-private').checked,enabled_adapters:[...document.querySelectorAll('#adapters input:checked')].map(x=>x.value),planner_provider:provider,model};
  if(type==='url') body.authorization={owner:$('auth-owner').value.trim(),ticket:$('auth-ticket').value.trim(),purpose:$('auth-purpose').value.trim(),expires_hours:24};
  try {const r=await api('/api/runs',{method:'POST',body:JSON.stringify(body)});renderRun(r);if(r.status!=='awaiting_approval')stream(r.run_id);history();$('live').scrollIntoView({behavior:'smooth'});} catch(err){$('form-error').textContent=err.message;show('form-error');}
};

async function dir(path=null){const d=await api('/api/fs'+(path?`?path=${encodeURIComponent(path)}`:''));S.path=d.path;S.parent=d.parent;$('browser-path').textContent=d.path;$('browser-list').innerHTML=d.directories.map(x=>`<button class="folder" data-path="${esc(x.path)}">▰ ${esc(x.name)}</button>`).join('')||'<div class="empty">No directories.</div>';document.querySelectorAll('.folder').forEach(x=>x.onclick=()=>dir(x.dataset.path));}
$('browse').onclick=async()=>{await dir($('local-path').value||null).catch(()=>dir());show('modal');};$('close').onclick=()=>show('modal',false);$('parent').onclick=()=>S.parent&&dir(S.parent);$('choose').onclick=()=>{$('local-path').value=S.path;show('modal',false);};
boot().catch(e=>{$('engine').textContent='Engine unavailable';console.error(e);});sev();agents();
