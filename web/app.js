const $ = id => document.getElementById(id);
const seconds = x => `${x.toFixed(2)} s`;
let sample;
async function load() {
  const [report, proof, series] = await Promise.all(['/data/report.json','/data/sample.json','/data/series.json'].map(async url => {
    const response = await fetch(url); if (!response.ok) throw new Error(`Could not load ${url}`); return response.json();
  }));
  if (!report.verified || !report.bind_verified || !report.byte_identical_zones) throw new Error('This result is not verified');
  sample = proof;
  const cpu=report.runs.cpu.total.median_seconds, gpu=report.runs.gpu.total.median_seconds;
  $('speedup').textContent=`${(cpu/gpu).toFixed(2)}×`;
  $('cpu-time').textContent=seconds(cpu); $('gpu-time').textContent=seconds(gpu);
  const max=Math.max(cpu,gpu); $('cpu-bar').style.width=`${cpu/max*100}%`; $('gpu-bar').style.width=`${gpu/max*100}%`;
  $('rrsets').textContent=report.rrsets_signed.toLocaleString();
  $('verified-label').textContent='BIND VERIFIED · IDENTICAL OUTPUT';
  $('run-description').textContent=`The recorded benchmark used ${report.input_a_records.toLocaleString()} hostnames and signed ${report.rrsets_signed.toLocaleString()} record sets on ${report.created_at.slice(0,10)}. No GPU is running behind this page.`;
  $('measurement').textContent=`Median of ${report.repeats} runs per backend on one EC2 g6.xlarge ($0.8048/hour list). Both paths use all ${report.threads} vCPUs; one of them also gets the L4.`;
  $('signing-result').textContent=`${(cpu/gpu).toFixed(2)}× faster end to end. Signing alone was ${report.speedup_sign.toFixed(2)}× faster; most of what’s left is Python parsing and writing zone files, which the GPU never touches.`;
  const table=document.createElement('table');
  table.innerHTML='<thead><tr><th>Hostnames</th><th>CPU total</th><th>GPU total</th><th>Speedup</th></tr></thead>';
  const body=document.createElement('tbody');
  for (const r of series) {
    const row=document.createElement('tr');
    for(const value of [r.input_a_records.toLocaleString(), seconds(r.runs.cpu.total.median_seconds), seconds(r.runs.gpu.total.median_seconds), `${r.speedup_total.toFixed(2)}×`]) { const cell=document.createElement('td'); cell.textContent=value;row.append(cell); }
    body.append(row);
  }
  table.append(body);$('timings').append(table);
  const phase=document.createElement('p');
  phase.textContent=`Median phase times for the main run. CPU: prepare ${seconds(report.runs.cpu.prepare.median_seconds)}, sign ${seconds(report.runs.cpu.sign.median_seconds)}, write ${seconds(report.runs.cpu.write.median_seconds)}. GPU: prepare ${seconds(report.runs.gpu.prepare.median_seconds)}, sign ${seconds(report.runs.gpu.sign.median_seconds)}, write ${seconds(report.runs.gpu.write.median_seconds)}. Phase medians don’t necessarily add up to the total median.`;
  $('timings').append(phase);
  $('record').textContent=proof.rrset;
  if (!window.crypto?.subtle) throw new Error('WebCrypto is unavailable in this browser');
  $('verify').disabled=false; $('tamper').disabled=false;
}
function bytes(b64) { return Uint8Array.from(atob(b64),c=>c.charCodeAt(0)); }
async function verify(tampered) {
  const status=$('verification');status.className='';status.textContent='Checking locally…';
  try {
    const key=await crypto.subtle.importKey('spki',bytes(sample.public_key_spki_base64),{name:'RSASSA-PKCS1-v1_5',hash:'SHA-256'},false,['verify']);
    const data=bytes(sample.canonical_base64); if(tampered) data[data.length-1]^=1;
    const ok=await crypto.subtle.verify('RSASSA-PKCS1-v1_5',key,bytes(sample.signature_base64),data);
    status.className=ok?'pass':'fail';
    status.textContent=tampered ? (ok?'Unexpected: altered record accepted.':'Rejected. One changed byte breaks the signature.') : (ok?'Valid. Your browser accepted the GPU’s signature.':'Invalid signature.');
  } catch(error) {status.className='fail';status.textContent=`Verification failed: ${error.message}`;}
}
$('verify').addEventListener('click',()=>verify(false));$('tamper').addEventListener('click',()=>verify(true));
load().catch(error=>{$('verified-label').textContent='RESULT UNAVAILABLE';$('verification').textContent=error.message;$('verification').className='fail';});
