'use strict';

// ── THEME ──
let isDark=true;
document.getElementById('themeBtn').addEventListener('click',()=>{
  isDark=!isDark;
  document.documentElement.setAttribute('data-theme',isDark?'dark':'light');
  document.getElementById('themeBtn').textContent=isDark?'🌙':'☀️';
  if(ALL.length)updateCharts();
});

// Strict hostname DNS toggle: when true, query hostnames exactly (including trailing $)
let strictHostNameDNS = false;
const strictBtn = document.getElementById('strictDnsBtn');
if(strictBtn){
  strictBtn.addEventListener('click',()=>{
    strictHostNameDNS = !strictHostNameDNS;
    strictBtn.textContent = 'Strict_Host_name_DNS: ' + (strictHostNameDNS ? 'ON' : 'OFF');
    strictBtn.classList.toggle('on', strictHostNameDNS);
  });
}

// ── PLATFORM ──
function detectPlatform(ou,aname,osv){
  const o=(ou||'').toLowerCase(),a=(aname||'').toLowerCase(),os=(osv||'').toLowerCase();
  if(o.includes('managed service accounts'))return 'SVC_ACCOUNT';
  if(a.includes('nessus')||a.includes('scanner')||a.includes('probe')||o.includes('nessus'))return 'SCANNER';
  if(o.includes('mac laptop')||o.includes('oct-macs')||o.includes('mac desktop')||o.includes('ou=mac'))return 'MAC';
  if(o.includes('ou=intune')||o.includes('intunedevices'))return 'WIN';
  if(o.includes('oct-virtualmachines'))return 'VM';
  if(o.includes('oct-servers')||o.includes('securitycompliance'))return 'SRV';
  if(o.includes('desktops')||o.includes('oct-computers')||o.includes('ou=desktops'))return 'WIN';
  if(os.includes('windows'))return 'WIN';
  if(os.includes('macos')||os.includes('mac os')||os.includes('osx')||os.includes('darwin'))return 'MAC';
  if(os.includes('linux')||os.includes('ubuntu')||os.includes('centos')||os.includes('rhel')||os.includes('debian'))return 'LNX';
  return 'UNK';
}
const PLAT_LABEL={WIN:'Windows',MAC:'macOS',LNX:'Linux',SRV:'Windows Server',VM:'Windows VM',DC:'Domain Controller',SVC_ACCOUNT:'Svc Account',SCANNER:'Scanner',UNK:'Unknown'};
const PLAT_CSS={WIN:'WIN',MAC:'MAC',LNX:'LNX',SRV:'SRV',VM:'VM',DC:'DC',SVC_ACCOUNT:'UNK',SCANNER:'UNK',UNK:'UNK'};

// ── SCORING ──
function scoreAsset(raw){
  const mac=(raw['MAC address']||'').trim(),osDir=(raw['OS version']||'').trim(),
        mfr=(raw['Manufacturer']||'').trim(),serial=(raw['Serial number']||'').trim(),
        ou=(raw['Organizational unit']||'').trim(),aname=(raw['Discovered asset name']||'').trim(),
        conf=(raw['Confidence']||'').trim();
  const disco=Math.max(1,parseInt(raw['Seen by (count)'])||1);
  const platform=detectPlatform(ou,aname,osDir);
  if(platform==='SVC_ACCOUNT')return{total:0,platform,autoClass:'SVC',osSource:'none',bd:{}};
  if(platform==='SCANNER')    return{total:0,platform,autoClass:'SCANNER',osSource:'none',bd:{}};
  const sMac=mac?35:0, sMfr=mfr?20:0, sSerial=serial?5:0;
  const ouL=ou.toLowerCase();
  const osInferMac=ouL.includes('mac laptop')||ouL.includes('oct-macs')||ouL.includes('mac desktop')||ouL.includes('ou=mac');
  const osInferWin=ouL.includes('ou=intune')||ouL.includes('intunedevices')||ouL.includes('desktops')||ouL.includes('oct-computers')||ouL.includes('oct-virtualmachines')||ouL.includes('ou=desktops');
  const osInferSrv=ouL.includes('oct-servers')||ouL.includes('securitycompliance');
  let sOs=0,osSource='none';
  if(osDir){sOs=30;osSource='direct';}
  else if(osInferMac||osInferWin||osInferSrv){sOs=25;osSource='inferred';}
  let sDisco=0;
  if(disco>=10)sDisco=30; else if(disco>=5)sDisco=20; else if(disco>=2)sDisco=10;
  const adJoined=ouL.includes('cn=')&&ouL.includes('dc=');
  const sAD=adJoined?20:0,sConf=conf.toLowerCase()==='high'?10:0,
        sSrv=osInferSrv?15:0,sVM=ouL.includes('oct-virtualmachines')?5:0;
  const total=sMac+sOs+sMfr+sSerial+sDisco+sAD+sConf+sSrv+sVM;
  return{total,platform,autoClass:null,osSource,bd:{mac:sMac,os:sOs,os_src:osSource,mfr:sMfr,serial:sSerial,disco:sDisco,ad:sAD,conf:sConf,srv:sSrv,vm:sVM}};
}

function parseTs(v){if(!v)return null;const s=String(v).trim();if(/^\d{4,5}(\.\d+)?$/.test(s)){const d=new Date((Number(s)-25569)*86400000);return isNaN(d)?null:d;}const d=new Date(s.replace(' ','T').replace('Z','+00:00'));return isNaN(d)?null:d;}
function lifeH(raw){const f=parseTs(raw['First seen']),l=parseTs(raw['Last seen']);if(!f||!l)return 0.5;return Math.max((l-f)/3600000,0.5);}
function lifeLabel(h){if(h<1)return'FLASH';if(h<24)return'TRANSIENT';if(h<168)return'PERSISTENT';return'ESTABLISHED';}
function densLabel(d){if(d<0.05)return'IDLE';if(d<0.5)return'SPORADIC';if(d<=2)return'REGULAR';return'ACTIVE';}

function classify(raw){
  const sc=scoreAsset(raw),lh=lifeH(raw),dis=Math.max(1,parseInt(raw['Seen by (count)'])||1),den=Math.round(dis/lh*1000)/1000;
  const lastSeenTs = parseTs(raw['Last seen']);
  let cls;
  if(sc.autoClass){cls=sc.autoClass;}
  else if(sc.total<25&&lh<1){cls='N0';}
  else if(sc.total<25&&den<0.05){cls='N1';}
  else if(sc.total<25){cls='N0';}
  else if(sc.total>=25&&sc.total<=54&&lh<24){cls='N2';}
  else if(sc.total>=25&&sc.total<=54){cls='N3';}
  else if(sc.total>=90&&lh>=24){cls='N5';}
  else if(sc.total>=55&&lh>=24){cls='N4';}
  else if(sc.total>=55&&lh<24){cls='N2';}
  else{cls='N3';}
  return{
    asset_name:(raw['Discovered asset name']|| raw['asset_name']||'').trim(),class:cls,score:sc.total,bd:sc.bd,
    platform:sc.platform,os_source:sc.osSource||'none',
    lifetime_hours:Math.round(lh*100)/100,lifetime_label:lifeLabel(lh),
    density:den,density_label:densLabel(den),discoverers:dis,
    confidence:(raw['Confidence']||'').trim(),
    last_seen: lastSeenTs? lastSeenTs.toISOString().replace('T',' ').split('.')[0] : (raw['Last seen']|| raw['LastSeen_UTC_readable']||'').trim(),
    last_seen_by:(raw['Last seen by (hostname)']||'').trim(),
    ip_last:(raw['IP address (last seen)']||'').trim(),
    mac:(raw['MAC address']||'').trim(),os:(raw['OS version']||'').trim(),
    manufacturer:(raw['Manufacturer']||'').trim(),
    ou:(raw['Organizational unit']||'').trim(),
    serial:(raw['Serial number']||'').trim(),
  };
}

// ── FILE PARSE ──
function processFile(file){
  const r=new FileReader();
  r.onload=e=>{
    try{
      let rows;
      if(file.name.toLowerCase().endsWith('.csv')){rows=parseCSV(e.target.result);}
      else{const wb=XLSX.read(e.target.result,{type:'array',cellDates:false});rows=XLSX.utils.sheet_to_json(wb.Sheets[wb.SheetNames[0]],{defval:''});}
      if(!rows.length){alert('No data rows found.');return;}
      ALL=rows.map(classify);refresh();showUI();
    }catch(err){alert('Parse error: '+err.message);console.error(err);}
  };
  file.name.toLowerCase().endsWith('.csv')?r.readAsText(file):r.readAsArrayBuffer(file);
}
function parseCSV(text){const lines=text.split(/\r?\n/).filter(l=>l.trim());if(lines.length<2)return[];const hdrs=splitCSV(lines[0]);return lines.slice(1).map(l=>{const vals=splitCSV(l),obj={};hdrs.forEach((h,i)=>{obj[h]=vals[i]??'';});return obj;});}
function splitCSV(line){const out=[];let cur='',inQ=false;for(let i=0;i<line.length;i++){const c=line[i];if(c==='"'){inQ=!inQ;continue}if(c===','&&!inQ){out.push(cur.trim());cur='';continue}cur+=c;}out.push(cur.trim());return out;}

// ── STATE ──
let ALL=[],filter='ALL',search='',hideNoise=false,sortCol=null,sortDir=1;
let donutChart=null,scoreChart=null,platformChart=null;
let DNS_RESULTS=[],dnsFilter='ALL';
const SUPPRESS=new Set(['N0','N1','SVC','SCANNER']);
const CLS_ORDER={N0:0,N1:1,N2:2,N3:3,N4:4,N5:5,SVC:6,SCANNER:7,REVIEW:8};
const CLS_LABEL={N0:'N0 · Noise',N1:'N1 · Ghost',N2:'N2 · Transient',N3:'N3 · Candidate',N4:'N4 · Unmanaged',N5:'N5 · Active Rogue',SVC:'SVC',SCANNER:'SCN · Scanner',REVIEW:'Review'};
const PRIO={N0:{l:'Suppress',c:'p-s'},N1:{l:'Suppress',c:'p-s'},N2:{l:'Low',c:'p-l'},N3:{l:'Medium',c:'p-m'},N4:{l:'High',c:'p-h'},N5:{l:'⚡ Critical',c:'p-c'},SVC:{l:'Suppress',c:'p-s'},SCANNER:{l:'Suppress',c:'p-s'},REVIEW:{l:'Review',c:'p-m'}};
const CLS_COLORS=['#6b7280','#3a78b0','#3d9e50','#c4a020','#d07030','#cc2840','#8060c8','#2890a0','#7878c0'];
const CLS_NAMES=['N0 Noise','N1 Ghost','N2 Transient','N3 Candidate','N4 Unmanaged','N5 Active Rogue','SVC','Scanner','Review'];
const CLS_KEYS=['N0','N1','N2','N3','N4','N5','SVC','SCANNER','REVIEW'];

function scColor(s){if(s>=90)return'#cc2840';if(s>=55)return'#d07030';if(s>=25)return'#c4a020';return'#6b7280';}
function getTextColor(){return isDark?'#8090b8':'#4a5878';}
function getGridColor(){return isDark?'rgba(255,255,255,.06)':'rgba(0,0,0,.06)';}

function showUI(){['chartsSection','legend','ctrl','rmeta','tshell'].forEach(id=>document.getElementById(id).classList.add('show'));}

function refresh(){updateKPI();updateLegend();updateCharts();renderTable();}

function updateKPI(){
  const noise=ALL.filter(r=>r.class==='N0'||r.class==='N1').length,
        action=ALL.filter(r=>r.class==='N4'||r.class==='N5').length,
        suppress=ALL.filter(r=>SUPPRESS.has(r.class)).length;
  document.getElementById('kTotal').textContent=ALL.length.toLocaleString();
  document.getElementById('kNoise').textContent=noise.toLocaleString();
  document.getElementById('kAction').textContent=action.toLocaleString();
  document.getElementById('kSuppress').textContent=suppress.toLocaleString();
  document.getElementById('donutTotal').textContent=ALL.length.toLocaleString();
}

function updateLegend(){
  const counts={};
  ALL.forEach(r=>{counts[r.class]=(counts[r.class]||0)+1;});
  // Update ALL card
  const total=ALL.length;
  const allPct = total? '100% of total' : '—';
  const cAllEl=document.getElementById('c-all'); if(cAllEl) cAllEl.textContent=total.toLocaleString();
  const pAllEl=document.getElementById('p-all'); if(pAllEl) pAllEl.textContent=allPct;
  ['N0','N1','N2','N3','N4','N5','SVC','SCANNER','REVIEW'].forEach(c=>{
    const n=counts[c]||0,pct=ALL.length?Math.round(n/ALL.length*100):0;
    const el=document.getElementById('c-'+c); if(el) el.textContent=n.toLocaleString();
    const pel=document.getElementById('p-'+c); if(pel) pel.textContent=ALL.length?pct+'% of total':'—';
  });
}

function updateCharts(){
  const counts={};CLS_KEYS.forEach(k=>counts[k]=0);
  ALL.forEach(r=>{if(counts[r.class]!==undefined)counts[r.class]++;});
  const donutData=CLS_KEYS.map(k=>counts[k]);
  if(donutChart){donutChart.data.datasets[0].data=donutData;donutChart.update('none');}
  else{const ctx=document.getElementById('donutChart').getContext('2d');donutChart=new Chart(ctx,{type:'doughnut',data:{labels:CLS_NAMES,datasets:[{data:donutData,backgroundColor:CLS_COLORS,borderWidth:2,borderColor:isDark?'#101520':'#ffffff',hoverOffset:4}]},options:{responsive:true,maintainAspectRatio:false,cutout:'68%',plugins:{legend:{display:false},tooltip:{callbacks:{label:ctx=>` ${ctx.label}: ${ctx.raw} (${ALL.length?Math.round(ctx.raw/ALL.length*100):0}%)`}}}}});}
  const buckets=new Array(10).fill(0);
  ALL.forEach(r=>{const b=Math.min(9,Math.floor(r.score/15));buckets[b]++;});
  const scoreLabels=['0–14','15–29','30–44','45–59','60–74','75–89','90–104','105–119','120–134','135+'];
  const scoreColors=scoreLabels.map((_,i)=>{const m=i*15+7;if(m>=90)return'#cc2840';if(m>=55)return'#d07030';if(m>=25)return'#c4a020';return'#6b7280';});
  if(scoreChart){scoreChart.data.datasets[0].data=buckets;scoreChart.data.datasets[0].backgroundColor=scoreColors;scoreChart.options.scales.x.ticks.color=getTextColor();scoreChart.options.scales.y.ticks.color=getTextColor();scoreChart.options.scales.x.grid.color=getGridColor();scoreChart.options.scales.y.grid.color=getGridColor();scoreChart.update('none');}
  else{const ctx2=document.getElementById('scoreChart').getContext('2d');scoreChart=new Chart(ctx2,{type:'bar',data:{labels:scoreLabels,datasets:[{data:buckets,backgroundColor:scoreColors,borderRadius:3,borderSkipped:false}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{x:{ticks:{color:getTextColor(),font:{size:8}},grid:{color:getGridColor()}},y:{ticks:{color:getTextColor(),font:{size:8}},grid:{color:getGridColor()}}}}});}
  const platCounts={};ALL.forEach(r=>{platCounts[r.platform]=(platCounts[r.platform]||0)+1;});
  const platEntries=Object.entries(platCounts).sort((a,b)=>b[1]-a[1]);
  const platLabels=platEntries.map(([k])=>PLAT_LABEL[k]||k),platVals=platEntries.map(([,v])=>v);
  const platColors=platEntries.map(([k])=>({WIN:'#4d7cfe',MAC:'#8060c8',LNX:'#3d9e50',SRV:'#d07030',VM:'#2890a0',DC:'#cc2840',UNK:'#6b7280',SVC_ACCOUNT:'#8060c8',SCANNER:'#2890a0'}[k]||'#6b7280'));
  if(platformChart){platformChart.data.labels=platLabels;platformChart.data.datasets[0].data=platVals;platformChart.data.datasets[0].backgroundColor=platColors;platformChart.options.scales.x.ticks.color=getTextColor();platformChart.options.scales.y.ticks.color=getTextColor();platformChart.options.scales.x.grid.color=getGridColor();platformChart.options.scales.y.grid.color=getGridColor();platformChart.update('none');}
  else{const ctx3=document.getElementById('platformChart').getContext('2d');platformChart=new Chart(ctx3,{type:'bar',data:{labels:platLabels,datasets:[{data:platVals,backgroundColor:platColors,borderRadius:3,borderSkipped:false}]},options:{responsive:true,maintainAspectRatio:false,indexAxis:'y',plugins:{legend:{display:false}},scales:{x:{ticks:{color:getTextColor(),font:{size:8}},grid:{color:getGridColor()}},y:{ticks:{color:getTextColor(),font:{size:9}},grid:{color:getGridColor()}}}}});}
}

// ── DNS VERIFICATION ──
let activeDnsClass = null;
let strictFilter = 'ALL';

async function runDNS(cls) {
  const assets = (cls && String(cls).toUpperCase() === 'ALL') ? ALL.slice() : ALL.filter(r => r.class === cls);
  if (!assets.length) { alert('No assets in class ' + cls); return; }

  activeDnsClass = cls;
  DNS_RESULTS = [];
  dnsFilter = 'ALL';

  // Reset panel
  const panel = document.getElementById('dnsPanel');
  panel.classList.add('show');
  panel.scrollIntoView({ behavior: 'smooth', block: 'start' });
  const panelLabel = (cls && String(cls).toUpperCase() === 'ALL') ? 'All' : (CLS_LABEL[cls] || cls);
  document.getElementById('dnsPanelClass').textContent = '— ' + panelLabel;
  document.getElementById('dnsTbody').innerHTML = '<tr><td colspan="8" class="dns-loading"><span class="dns-spinner"></span>Resolving ' + assets.length + ' hostnames via system DNS…</td></tr>';
  document.getElementById('dnsTotal').textContent = assets.length;
  document.getElementById('dnsResolved').textContent = '0';
  document.getElementById('dnsUnresolved').textContent = '0';
  document.getElementById('dnsTimeout').textContent = '0';
  document.getElementById('dnsProgressBar').style.width = '0%';

  // Update button state
  document.querySelectorAll('.lc-dns-btn[data-cls="'+cls+'"]').forEach(b => { b.classList.add('running'); b.textContent = '⟳ Running…'; });
  document.querySelectorAll('.dns-filter-btn').forEach(b => b.classList.toggle('on', b.dataset.df === 'ALL'));

  // Build hostname list; track assets that end with $ and optionally strip $ for queries unless strict mode is enabled
  const hostnames = assets.map(a => a.asset_name || a['Discovered asset name'] || a['hostname'] || '');
  const isDollarFlag = hostnames.map(h => typeof h === 'string' && h.endsWith('$'));
  const hostnamesForQuery = hostnames.map((h, i) => {
    if (!h) return h;
    if (isDollarFlag[i]) return strictHostNameDNS ? h : h.slice(0, -1);
    return h;
  });
  // update header stat for assets with $ and init per-type counters
  const dollarCount = isDollarFlag.filter(Boolean).length;
  let dollarResolved = 0, dollarUnresolved = 0, dollarTimeout = 0;
  const dollarEl = document.getElementById('dnsDollar'); if(dollarEl) dollarEl.textContent = dollarCount;
  const dollarResEl = document.getElementById('dnsDollarResolved'); if(dollarResEl) dollarResEl.textContent = dollarResolved;
  const dollarUnresEl = document.getElementById('dnsDollarUnresolved'); if(dollarUnresEl) dollarUnresEl.textContent = dollarUnresolved;
  const BATCH = 20;
  let resolved = 0, unresolved = 0, timeouts = 0, done = 0;

  for (let i = 0; i < hostnames.length; i += BATCH) {
    const batch = hostnamesForQuery.slice(i, i + BATCH);
    const origBatch = hostnames.slice(i, i + BATCH);
    const isDollarBatch = isDollarFlag.slice(i, i + BATCH);
    const assetBatch = assets.slice(i, i + BATCH);

    try {
      const resp = await fetch('/resolve', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ hostnames: batch })
      });
      const data = await resp.json();

      data.results.forEach((r, idx) => {
        // Determine the actual queried name for dollar-assets depending on strict mode
        const queriedName = isDollarBatch[idx] ? (strictHostNameDNS ? origBatch[idx] : origBatch[idx].replace(/\$$/,'')) : '';
        const assetsDollar = isDollarBatch[idx] ? { wasDollar: true, queried: queriedName, hostname: r.hostname || '', status: r.status || '', resolved_ip: r.resolved_ip || '', reverse: r.reverse || '' } : { wasDollar: false };
        DNS_RESULTS.push({ ...assetBatch[idx], dns: r, assets_with_dollar: assetsDollar });
        if (r.status === 'resolved') resolved++;
        else if (r.status === 'timeout') timeouts++;
        else unresolved++;
        // update dollar-specific counters
        if (isDollarBatch[idx]){
          if (r.status === 'resolved') dollarResolved++;
          else if (r.status === 'timeout') dollarTimeout++;
          else dollarUnresolved++;
        }
      });
    } catch (e) {
      // Server not available — mark batch as error
      assetBatch.forEach((a, idx) => {
        const qname = batch[idx];
        const wasDollar = isDollarBatch[idx];
        const queriedName = wasDollar ? (strictHostNameDNS ? origBatch[idx] : origBatch[idx].replace(/\$$/,'')) : '';
        const assetsDollar = wasDollar ? { wasDollar: true, queried: queriedName, hostname: qname, status: 'error', resolved_ip: '', reverse: '', error: 'Server unavailable' } : { wasDollar: false };
        DNS_RESULTS.push({ ...a, dns: { hostname: qname, status: 'error', resolved_ip: '', reverse: '', error: 'Server unavailable' }, assets_with_dollar: assetsDollar });
        unresolved++;
        if (wasDollar) dollarUnresolved++;
      });
    }

    done += batch.length;
    document.getElementById('dnsProgressBar').style.width = Math.round(done / hostnames.length * 100) + '%';
    document.getElementById('dnsResolved').textContent = resolved;
    document.getElementById('dnsUnresolved').textContent = unresolved;
    document.getElementById('dnsTimeout').textContent = timeouts;
    if(dollarResEl) dollarResEl.textContent = dollarResolved;
    if(dollarUnresEl) dollarUnresEl.textContent = dollarUnresolved;
    renderDNSTable();
    renderStrictTable();
  }

  // Done
  document.getElementById('dnsProgressBar').style.width = '100%';
  document.querySelectorAll('.lc-dns-btn[data-cls="'+cls+'"]').forEach(b => { b.classList.remove('running'); b.classList.add('done'); b.textContent = '✓ Done (' + resolved + '/' + assets.length + ')'; });
}

function renderDNSTable() {
  let data = DNS_RESULTS;
  if (dnsFilter !== 'ALL') data = data.filter(r => r.dns.status === dnsFilter);

  const tbody = document.getElementById('dnsTbody');
  if (!data.length) { tbody.innerHTML = '<tr><td colspan="9" class="empty">No results match filter</td></tr>'; return; }

  tbody.innerHTML = data.map(r => {
    const d = r.dns;
    const badgeClass = 'dns-badge dns-badge-' + (d.status === 'error' ? 'error' : d.status);
    return `<tr>
      <td style="font-weight:500;color:var(--text)">${r.asset_name || '—'}</td>
      <td><span class="cls cls-${r.class}">${CLS_LABEL[r.class] || r.class}</span></td>
      <td style="font-variant-numeric:tabular-nums;color:${scColor(r.score)}">${r.score}</td>
      <td style="color:var(--text2)">${r.last_seen || '—'}</td>
      <td style="color:var(--text2)">${d.hostname || '—'}</td>
      <td><span class="${badgeClass}">${d.status}</span></td>
      <td class="dns-ip">${d.resolved_ip || '—'}</td>
      <td style="color:var(--text2)">${r.assets_with_dollar && r.assets_with_dollar.wasDollar ? (r.assets_with_dollar.queried + ' → ' + (r.assets_with_dollar.resolved_ip || r.assets_with_dollar.status)) : '—'}</td>
      <td style="color:var(--text3)">${d.reverse || '—'}</td>
    </tr>`;
  }).join('');
}

function renderStrictTable(){
  const strictData = DNS_RESULTS.filter(r=>r.assets_with_dollar && r.assets_with_dollar.wasDollar);
  const tbody = document.getElementById('strictTbody');
  document.getElementById('strictTotal').textContent = strictData.length;
  const resolved = strictData.filter(r=>r.dns.status==='resolved').length;
  const unresolved = strictData.filter(r=>r.dns.status==='unresolved' || r.dns.status==='error').length;
  const timeouts = strictData.filter(r=>r.dns.status==='timeout').length;
  document.getElementById('strictResolved').textContent = resolved;
  document.getElementById('strictUnresolved').textContent = unresolved;
  document.getElementById('strictTimeout').textContent = timeouts;
  let data = strictData;
  if(strictFilter!=='ALL') data = data.filter(r=>r.dns.status===strictFilter);
  if(!data.length){tbody.innerHTML = '<tr><td colspan="8" class="empty">No strict-host results match filter</td></tr>';return}
  tbody.innerHTML = data.map(r=>{
    const d=r.dns; return `<tr>
      <td style="font-weight:500;color:var(--text)">${r.asset_name||'—'}</td>
      <td><span class="cls cls-${r.class}">${CLS_LABEL[r.class]||r.class}</span></td>
      <td style="font-variant-numeric:tabular-nums;color:${scColor(r.score)}">${r.score}</td>
      <td style="color:var(--text2)">${r.last_seen||'—'}</td>
      <td style="color:var(--text2)">${r.assets_with_dollar.queried||d.hostname||'—'}</td>
      <td><span class="dns-badge dns-badge-${d.status==='error'?'error':d.status}">${d.status}</span></td>
      <td class="dns-ip">${d.resolved_ip||'—'}</td>
      <td style="color:var(--text3)">${d.reverse||'—'}</td>
    </tr>`}).join('');
}

// Strict filter buttons
document.getElementById('strictFilterAll').addEventListener('click',()=>{document.querySelectorAll('#strictDnsWrap .dns-filter-btn').forEach(b=>b.classList.remove('on'));document.getElementById('strictFilterAll').classList.add('on');strictFilter='ALL';renderStrictTable();});
document.getElementById('strictFilterRes').addEventListener('click',()=>{document.querySelectorAll('#strictDnsWrap .dns-filter-btn').forEach(b=>b.classList.remove('on'));document.getElementById('strictFilterRes').classList.add('on');strictFilter='resolved';renderStrictTable();});
document.getElementById('strictFilterUnres').addEventListener('click',()=>{document.querySelectorAll('#strictDnsWrap .dns-filter-btn').forEach(b=>b.classList.remove('on'));document.getElementById('strictFilterUnres').classList.add('on');strictFilter='unresolved';renderStrictTable();});
document.getElementById('strictFilterTimeout').addEventListener('click',()=>{document.querySelectorAll('#strictDnsWrap .dns-filter-btn').forEach(b=>b.classList.remove('on'));document.getElementById('strictFilterTimeout').classList.add('on');strictFilter='timeout';renderStrictTable();});

// strict export
document.getElementById('strictExportBtn').addEventListener('click',()=>{
  const data = DNS_RESULTS.filter(r=>r.assets_with_dollar && r.assets_with_dollar.wasDollar);
  if(!data.length) return;
  const cols=['asset_name','class','score','last_seen','assets_with_dollar.queried','assets_with_dollar.status','assets_with_dollar.resolved_ip','dns.hostname','dns.status','dns.resolved_ip','dns.reverse','dns.error'];
  const csv=[cols.join(','),...data.map(r=>cols.map(c=>{const parts=c.split('.');let v=r;parts.forEach(p=>{v=v?.[p];});return typeof v==='string'&&v.includes(',')?`"${v}"`:v??'';}).join(','))].join('\n');
  const a=document.createElement('a');a.href='data:text/csv;charset=utf-8,'+encodeURIComponent(csv);a.download=`strict_dns_${activeDnsClass||'ALL'}_${new Date().toISOString().slice(0,10)}.csv`;a.click();
});

// ── TABLE RENDER ──
function getFiltered(){
  let data=ALL;
  if(hideNoise)data=data.filter(r=>!SUPPRESS.has(r.class));
  if(filter!=='ALL')data=data.filter(r=>r.class===filter);
  if(search){const q=search.toLowerCase();data=data.filter(r=>r.asset_name.toLowerCase().includes(q)||r.last_seen_by.toLowerCase().includes(q)||r.ip_last.toLowerCase().includes(q)||r.manufacturer.toLowerCase().includes(q)||r.os.toLowerCase().includes(q)||r.ou.toLowerCase().includes(q)||(PLAT_LABEL[r.platform]||'').toLowerCase().includes(q));}
  if(sortCol){data=[...data].sort((a,b)=>{let va=a[sortCol],vb=b[sortCol];if(sortCol==='class'){va=CLS_ORDER[va]??9;vb=CLS_ORDER[vb]??9;}return(va<vb?-1:va>vb?1:0)*sortDir;});}
  return data;
}

function renderTable(){
  const data=getFiltered(),supp=ALL.filter(r=>SUPPRESS.has(r.class)).length;
  document.getElementById('rcTxt').textContent=`Showing ${data.length.toLocaleString()} of ${ALL.length.toLocaleString()} assets`;
  document.getElementById('noisePill').textContent=`${supp.toLocaleString()} suppressible`;
  const tbody=document.getElementById('tbody');
  if(!data.length){tbody.innerHTML='<tr><td colspan="18" class="empty">No assets match current filter</td></tr>';return;}
  tbody.innerHTML=data.map(r=>{
    const p=PRIO[r.class]||PRIO.REVIEW,bw=Math.min(100,(r.score/165)*100).toFixed(1),col=scColor(r.score);
    const bd=r.bd,tip=`MAC: ${bd.mac||0}  OS: ${bd.os||0} (${r.os_source})  Mfr: ${bd.mfr||0}\nSerial: ${bd.serial||0}  Disco: ${bd.disco||0}  AD: ${bd.ad||0}\nConf: ${bd.conf||0}  Server: ${bd.srv||0}  VM: ${bd.vm||0}\n─────────────────\nTotal: ${r.score}`;
    const isSup=SUPPRESS.has(r.class)&&!hideNoise,ouShort=r.ou.length>38?r.ou.substring(0,38)+'…':r.ou,platC=PLAT_CSS[r.platform]||'UNK';
    return `<tr class="${isSup?'sup':''}">
      <td class="td-id" title="${r.asset_name}">${r.asset_name||'—'}</td>
      <td><span class="cls cls-${r.class}">${CLS_LABEL[r.class]||r.class}</span></td>
      <td><span class="prio ${p.c}">${p.l}</span></td>
      <td data-tip="${tip}"><div class="sc-w"><span class="sc-n" style="color:${col}">${r.score}</span><div class="sc-t"><div class="sc-f" style="width:${bw}%;background:${col}"></div></div></div></td>
      <td><span class="plat plat-${platC}">${PLAT_LABEL[r.platform]||r.platform}</span></td>
      <td style="font-variant-numeric:tabular-nums">${r.lifetime_hours.toFixed(1)}</td>
      <td><span class="lb life-${r.lifetime_label}">${r.lifetime_label}</span></td>
      <td style="font-variant-numeric:tabular-nums">${r.density}</td>
      <td><span class="lb dens-${r.density_label}">${r.density_label}</span></td>
      <td style="text-align:center">${r.discoverers}</td>
      <td><span class="${r.confidence==='High'?'conf-H':'conf-L'}">${r.confidence||'—'}</span></td>
      <td style="color:var(--text2)">${r.last_seen_by||'—'}</td>
      <td style="color:var(--text2)">${r.ip_last||'—'}</td>
      <td class="${r.mac?'bool-y':'bool-n'}">${r.mac?'✓ '+r.mac.substring(0,8)+'…':'—'}</td>
      <td style="color:var(--text2)">${r.os||'—'}</td>
      <td style="color:var(--text2)">${r.manufacturer||'—'}</td>
      <td style="color:var(--text3);font-size:10px" title="${r.ou}">${ouShort||'—'}</td>
      <td class="${r.serial?'bool-y':'bool-n'}">${r.serial||'—'}</td>
    </tr>`;
  }).join('');
}

// ── EVENTS ──
const dz=document.getElementById('dz');
dz.addEventListener('dragover',e=>{e.preventDefault();dz.classList.add('over')});
dz.addEventListener('dragleave',()=>dz.classList.remove('over'));
dz.addEventListener('drop',e=>{e.preventDefault();dz.classList.remove('over');const f=e.dataTransfer.files[0];if(f)processFile(f)});
dz.addEventListener('click',e=>{if(e.target.tagName!=='BUTTON')document.getElementById('fi').click()});
document.getElementById('fi').addEventListener('change',e=>{if(e.target.files[0])processFile(e.target.files[0])});

// DNS buttons on legend cards
document.querySelectorAll('.lc-dns-btn').forEach(btn=>{
  btn.addEventListener('click',e=>{e.stopPropagation();const cls=btn.dataset.cls;if(!ALL.length){alert('Upload a file first.');return;}if(btn.classList.contains('running'))return;runDNS(cls);});
});

// DNS panel filter
document.querySelectorAll('.dns-filter-btn').forEach(btn=>{
  btn.addEventListener('click',()=>{
    document.querySelectorAll('.dns-filter-btn').forEach(b=>b.classList.remove('on'));
    btn.classList.add('on');dnsFilter=btn.dataset.df;renderDNSTable();
  });
});

// DNS close
document.getElementById('dnsClose').addEventListener('click',()=>{
  document.getElementById('dnsPanel').classList.remove('show');
  if(activeDnsClass){document.querySelectorAll('.lc-dns-btn[data-cls="'+activeDnsClass+'"]').forEach(b=>{b.classList.remove('done');b.textContent='⌕ Verify DNS';});}
});

// DNS export
document.getElementById('dnsExportBtn').addEventListener('click',()=>{
  if(!DNS_RESULTS.length)return;
  let data=DNS_RESULTS;
  if(dnsFilter!=='ALL')data=data.filter(r=>r.dns.status===dnsFilter);
  const cols=['asset_name','class','score','last_seen','assets_with_dollar.resolved_ip','assets_with_dollar.status','dns.hostname','dns.status','dns.resolved_ip','dns.reverse','dns.error'];
  const csv=[cols.join(','),...data.map(r=>cols.map(c=>{const parts=c.split('.');let v=r;parts.forEach(p=>{v=v?.[p];});return typeof v==='string'&&v.includes(',')? `"${v}"`:v??'';}).join(','))].join('\n');
  const a=document.createElement('a');
  a.href='data:text/csv;charset=utf-8,'+encodeURIComponent(csv);
  a.download=`dns_verify_${activeDnsClass}_${new Date().toISOString().slice(0,10)}.csv`;
  a.click();
});

// Legend click filter
document.querySelectorAll('.lc').forEach(card=>{
  card.addEventListener('click',()=>{
    const c=card.dataset.cls;
    if(filter===c){filter='ALL';card.classList.remove('active');}
    else{document.querySelectorAll('.lc').forEach(x=>x.classList.remove('active'));card.classList.add('active');filter=c;}
    document.querySelectorAll('.cbtn').forEach(b=>b.classList.remove('on'));
    renderTable();
  });
});

document.querySelectorAll('.cbtn[data-f]').forEach(btn=>{
  btn.addEventListener('click',()=>{
    document.querySelectorAll('.cbtn').forEach(b=>b.classList.remove('on'));
    document.querySelectorAll('.lc').forEach(x=>x.classList.remove('active'));
    btn.classList.add('on');filter=btn.dataset.f;
    if(filter!=='ALL'){const c=document.querySelector(`.lc[data-cls="${filter}"]`);if(c)c.classList.add('active');}
    renderTable();
  });
});

document.getElementById('srch').addEventListener('input',e=>{search=e.target.value;renderTable();});
document.getElementById('tog').addEventListener('click',function(){hideNoise=!hideNoise;this.classList.toggle('on',hideNoise);renderTable();});
document.querySelectorAll('th[data-col]').forEach(th=>{
  th.addEventListener('click',()=>{
    const c=th.dataset.col;if(sortCol===c)sortDir*=-1;else{sortCol=c;sortDir=1;}
    document.querySelectorAll('th').forEach(t=>{t.classList.remove('sorted');if(t.querySelector('.arr'))t.querySelector('.arr').textContent='↕';});
    th.classList.add('sorted');if(th.querySelector('.arr'))th.querySelector('.arr').textContent=sortDir===1?'↑':'↓';
    renderTable();
  });
});
document.getElementById('expbtn').addEventListener('click',()=>{
  const data=getFiltered();if(!data.length)return;
  const cols=['asset_name','class','score','platform','lifetime_hours','lifetime_label','density','density_label','discoverers','confidence','last_seen_by','ip_last','mac','os','manufacturer','ou','serial'];
  const csv=[cols.join(','),...data.map(r=>cols.map(c=>{const v=r[c];return typeof v==='string'&&v.includes(',')? `"${v}"`:v??'';}).join(','))].join('\n');
  const a=document.createElement('a');a.href='data:text/csv;charset=utf-8,'+encodeURIComponent(csv);a.download=`cs_classified_v4_${new Date().toISOString().slice(0,10)}.csv`;a.click();
});

// ── RESIZABLE COLUMNS ──
function makeTableResizable(selector){
  document.querySelectorAll(selector).forEach(table=>{
    const ths = table.querySelectorAll('th');
    ths.forEach((th, idx)=>{
      // avoid duplicating resizer
      if(th.querySelector('.col-resizer')) return;
      const res = document.createElement('div'); res.className='col-resizer'; th.appendChild(res);
      const start = e => {
        e.preventDefault();
        const startX = (e.touches?e.touches[0].pageX:e.pageX);
        const startW = th.offsetWidth;
        function move(ev){
          const curX = (ev.touches?ev.touches[0].pageX:ev.pageX);
          const dx = curX - startX;
          const newW = Math.max(40, startW + dx);
          th.style.width = newW + 'px';
          // apply to all cells in column
          table.querySelectorAll('tr').forEach(row=>{
            const cell = row.children[idx]; if(cell) cell.style.width = newW + 'px';
          });
        }
        function up(){document.removeEventListener('mousemove',move);document.removeEventListener('mouseup',up);document.removeEventListener('touchmove',move);document.removeEventListener('touchend',up);}
        document.addEventListener('mousemove',move);document.addEventListener('mouseup',up);
        document.addEventListener('touchmove',move);document.addEventListener('touchend',up);
      };
      res.addEventListener('mousedown',start);
      res.addEventListener('touchstart',start,{passive:false});
    });
  });
}

// initialize resizable columns for main and DNS tables
document.addEventListener('DOMContentLoaded',()=>{
  makeTableResizable('#tbl');
  makeTableResizable('.dns-table');
  makeTableResizable('.strict-dns-table');
});

// Table expand/collapse handlers
document.querySelectorAll('.tbl-expand').forEach(btn=>{
  btn.addEventListener('click',()=>{
    const targetId = btn.dataset.target;
    const target = document.getElementById(targetId);
    if(!target) return;
    const expanded = target.classList.toggle('expanded');
    btn.textContent = expanded ? '⤡' : '⤢';
  });
});