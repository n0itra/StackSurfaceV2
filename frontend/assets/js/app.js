const state={
  page:'dashboard',
  scanId:null,
  scan:null,
  assetTab:'subdomains',
  ffufRunId:null,
  ffufEventSource:null,
  scanEventSource:null,
  selectedProfile:'full',
  resourceRows:[],
  resourceRes:null,
  resourceHostId:null,
  resourceSort:{field:null,direction:'asc'}
};

const profileSummary={
  full:'runs the complete discovery, infrastructure, web and vulnerability pipeline.',
  discovery:'finds subdomains, resolves them and keeps the requested HTTP statuses.',
  web:'works from the current target surface and focuses on crawling, endpoints, technologies and WAF.',
  vuln:'uses the existing web surface for Nuclei, JavaScript and secret analysis.'
};

const terminalStatuses=new Set([
  'completed',
  'completed_with_warnings',
  'failed',
  'cancelled'
]);

const $=id=>document.getElementById(id);

function esc(v){
  return String(v??'').replace(/[&<>'"]/g,c=>({
    '&':'&amp;',
    '<':'&lt;',
    '>':'&gt;',
    "'":'&#39;',
    '"':'&quot;'
  }[c]));
}

function hideScanIds(v){
  return String(v??'')
    .replace(
      /[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}/gi,
      ''
    )
    .replace(/\s{2,}/g,' ')
    .trim();
}

function toast(msg){
  $('toast').textContent=hideScanIds(msg);
  $('toast').classList.add('show');
  setTimeout(()=>$('toast').classList.remove('show'),4500)
}

async function api(url,opts={}){
  const r=await fetch(
    url,
    {
      headers:{
        'Content-Type':'application/json',
        ...(opts.headers||{})
      },
      ...opts
    }
  );

  let data=null;

  try{
    data=await r.json()
  }catch{}

  if(!r.ok){
    const msg=
      data?.detail?.message||
      data?.detail||
      data?.message||
      `Request failed (${r.status})`;

    throw new Error(
      typeof msg==='string'
        ? msg
        : JSON.stringify(msg)
    );
  }

  return data;
}

function openPage(page){
  stopScanStream();
  stopFfufStream();

  state.page=page;

  document
    .querySelectorAll('.page')
    .forEach(
      p=>p.classList.remove('active')
    );

  const el=$('page-'+page);

  if(el){
    el.classList.add('active');
  }

  document
    .querySelectorAll('#nav button')
    .forEach(
      b=>b.classList.toggle(
        'active',
        b.dataset.page===page
      )
    );

  renderPage();
}

function renderPage(){
  if(state.page==='dashboard'){
    loadDashboard();
  }else if(state.page==='scans'){
    loadScans();
  }else if(state.page==='assets'){
    loadAssets();
  }else if(state.page==='changes'){
    loadChanges();
  }else if(state.page==='findings'){
    loadFindings();
  }else if(state.page==='scan-detail'){
    loadScanDetail();
  }else if(state.page==='scan-ffuf'){
    renderFfufPage();
  }
}

function stopScanStream(){
  if(state.scanEventSource){
    state.scanEventSource.close();
    state.scanEventSource=null
  }
}

function stopFfufStream(){
  if(state.ffufEventSource){
    state.ffufEventSource.close();
    state.ffufEventSource=null
  }
}

function setEngine(healthy){
  $('healthPill').textContent=
    healthy?'ONLINE':'DEGRADED';

  $('healthPill').style.borderColor=
    healthy?'#24513f':'#5b313b';

  $('healthText').textContent=
    healthy
      ? 'API · PostgreSQL · Redis'
      : 'Check /api/health';

  $('engineBar').style.width=
    healthy?'100%':'30%';
}

async function refreshHealth(){
  try{
    const d=await api('/api/health');
    setEngine(d.status==='ok')
  }catch{
    setEngine(false)
  }
}

async function activeScan(){
  const scans=
    await api('/api/scans?limit=10');

  return scans.find(
    s=>[
      'queued',
      'running',
      'stopping'
    ].includes(s.status)
  )||null
}

async function syncHeader(){
  try{
    const a=await activeScan();

    $('newScanBtn').disabled=!!a;

    $('newScanBtn').title=
      a
        ? 'A scan is already active'
        : 'Start a new scan';
  }catch{}
}

function profileSelect(name){
  state.selectedProfile=name;

  document
    .querySelectorAll('.compact-scan-type')
    .forEach(
      x=>x.classList.toggle(
        'selected',
        x.dataset.profile===name
      )
    );

  $('profileSummary').innerHTML=`
    <strong>${
      name==='full'
        ? 'Full Recon'
        : name==='discovery'
          ? 'Discovery'
          : name==='web'
            ? 'Web Surface'
            : 'Vulnerability Focus'
    }</strong>
    ${profileSummary[name]}
  `
}

function selectProfile(name){
  profileSelect(name)
}

function openModal(){
  syncHeader().then(()=>{
    if($('newScanBtn').disabled){
      toast(
        'A scan is already running. Stop it before starting another.'
      );
      return
    }

    $('scanModal').classList.add('show');
    profileSelect(state.selectedProfile)
  })
}

function closeModal(){
  $('scanModal').classList.remove('show')
}

async function createScan(){
  const links=
    $('targetLinks')
      .value
      .split(/\n|,/)
      .map(x=>x.trim())
      .filter(Boolean);

  if(!links.length){
    toast('Enter at least one target link.');
    return
  }

  const btn=$('startScanBtn');

  btn.disabled=true;
  btn.textContent='Starting…';

  try{
    const scan=
      await api(
        '/api/scans',
        {
          method:'POST',
          body:JSON.stringify({
            links,
            scan_type:state.selectedProfile
          })
        }
      );

    closeModal();

    state.scanId=scan.id;
    state.scan=scan;

    openPage('scan-detail');

    toast('Scan started.');

  }catch(e){
    toast(e.message)

  }finally{
    btn.disabled=false;
    btn.textContent='Start Scan';
    syncHeader()
  }
}

async function stopScan(id){
  if(
    !confirm(
      'Stop this scan? The running security tool will be terminated and the scan will be marked stopped.'
    )
  ){
    return
  }

  try{
    await api(
      `/api/scans/${id}/stop`,
      {
        method:'POST'
      }
    );

    toast('Stop requested.');
    openScan(id)

  }catch(e){
    toast(e.message)
  }
}

function openScan(id){
  state.scanId=id;
  openPage('scan-detail')
}

function statusBadge(status){
  const map={
    running:'cyan',
    stopping:'yellow',
    queued:'yellow',
    completed:'green',
    completed_with_warnings:'yellow',
    failed:'red',
    cancelled:'gray'
  };

  return `
    <span class="badge ${map[status]||'gray'}">
      ${esc(
        status
          .replaceAll('_',' ')
          .toUpperCase()
      )}
    </span>
  `
}

function statusDot(status){
  const c=
    status==='running'
      ? 'run'
      : status==='stopping'||status==='queued'
        ? 'warn-dot'
        : terminalStatuses.has(status)
          ? 'ok'
          : 'bad-dot';

  return `
    <span class="status">
      <i class="${c}"></i>
      ${esc(status.replaceAll('_',' '))}
    </span>
  `
}


/* =========================================================
   Resource table helpers
   ========================================================= */

function isIpAddress(value){
  const s=String(value??'').trim();

  if(!s){
    return false;
  }

  if(
    /^(?:\d{1,3}\.){3}\d{1,3}$/.test(s)
  ){
    return s
      .split('.')
      .every(
        part=>
          Number(part)>=0 &&
          Number(part)<=255
      );
  }

  return (
    /^[0-9a-fA-F:]+$/.test(s) &&
    s.includes(':')
  );
}


function faviconMarkup(url){
  try{
    const u=new URL(url);
    const favicon=`${u.origin}/favicon.ico`;

    return `
      <span
        class="webapp-icon"
        aria-hidden="true"
        style="
          display:inline-flex;
          align-items:center;
          justify-content:center;
          width:18px;
          height:18px;
          margin-right:8px;
          vertical-align:middle
        "
      >
        <img
          src="${esc(favicon)}"
          alt=""
          loading="lazy"
          style="
            width:18px;
            height:18px;
            object-fit:contain;
            border-radius:4px
          "
          onerror="
            this.style.display='none';
            this.nextElementSibling.style.display='inline-flex'
          "
        >

        <span
          class="webapp-fallback"
          style="
            display:none;
            align-items:center;
            justify-content:center;
            width:18px;
            height:18px;
            border:1px solid #2b3d52;
            border-radius:4px;
            font-size:11px;
            color:#7f96aa
          "
        >
          ◉
        </span>
      </span>
    `;

  }catch{
    return `
      <span
        class="webapp-icon"
        aria-hidden="true"
        style="
          display:inline-flex;
          align-items:center;
          justify-content:center;
          width:18px;
          height:18px;
          margin-right:8px;
          vertical-align:middle
        "
      >
        <span
          class="webapp-fallback"
          style="
            display:inline-flex;
            align-items:center;
            justify-content:center;
            width:18px;
            height:18px;
            border:1px solid #2b3d52;
            border-radius:4px;
            font-size:11px;
            color:#7f96aa
          "
        >
          ◉
        </span>
      </span>
    `;
  }
}


function normalizeSortValue(value){
  if(Array.isArray(value)){
    return value.join(', ');
  }

  if(
    value===null||
    value===undefined
  ){
    return '';
  }

  return String(value);
}


function compareResourceValues(a,b,field){
  const av=a?.[field];
  const bv=b?.[field];

  const aEmpty=
    av===null||
    av===undefined||
    av==='';

  const bEmpty=
    bv===null||
    bv===undefined||
    bv==='';

  /*
   * Empty values always go to the bottom.
   */
  if(aEmpty&&bEmpty){
    return 0;
  }

  if(aEmpty){
    return 1;
  }

  if(bEmpty){
    return -1;
  }

  /*
   * Numeric columns use real numeric comparison.
   *
   * This is important for status codes:
   *
   * 200
   * 401
   * 403
   * 404
   *
   * rather than lexicographical ordering.
   */
  if(
    field==='status_code'||
    field==='port'||
    field==='words'||
    field==='lines'||
    field==='size'
  ){
    const an=Number(av);
    const bn=Number(bv);

    if(
      !Number.isNaN(an) &&
      !Number.isNaN(bn)
    ){
      return an-bn;
    }
  }

  /*
   * Technologies, WAF names, URLs,
   * hostnames, etc. are sorted naturally.
   */
  return normalizeSortValue(av).localeCompare(
    normalizeSortValue(bv),
    undefined,
    {
      numeric:true,
      sensitivity:'base'
    }
  );
}


function sortIndicator(field){
  if(
    state.resourceSort.field!==field
  ){
    return '';
  }

  return state.resourceSort.direction==='asc'
    ? ' ↑'
    : ' ↓';
}


function setResourceSort(field){
  if(
    state.resourceSort.field===field
  ){
    state.resourceSort.direction=
      state.resourceSort.direction==='asc'
        ? 'desc'
        : 'asc';
  }else{
    state.resourceSort.field=field;
    state.resourceSort.direction='asc';
  }

  rerenderCurrentResourceTable();
}


function resourceDisplay(row,field,res){
  const value=row?.[field];

  if(field==='url'){
    return `
      <div class="webapp-url">
        ${
          res==='alive'
            ? faviconMarkup(value)
            : ''
        }

        <span class="mono">
          ${esc(value??'—')}
        </span>
      </div>
    `;
  }

  /*
   * Never display a hostname in the IP column.
   */
  if(field==='ip'){
    return isIpAddress(value)
      ? `
          <span class="mono">
            ${esc(value)}
          </span>
        `
      : `
          <span class="muted">
            —
          </span>
        `;
  }

  if(field==='technologies'){
    return esc(
      Array.isArray(value)
        ? value.join(', ')
        : (value??'—')
    );
  }

  if(field==='sources'){
    return esc(
      Array.isArray(value)
        ? value.join(', ')
        : (value??'—')
    );
  }

  if(field==='hostnames'){
    return esc(
      Array.isArray(value)
        ? value.join(', ')
        : (value??'—')
    );
  }

  if(field==='status_code'){
    return (
      value===null||
      value===undefined||
      value===''
    )
      ? `
          <span class="muted">
            —
          </span>
        `
      : esc(value);
  }

  if(field==='waf_name'){
    return esc(value||'—');
  }

  if(typeof value==='boolean'){
    return value
      ? 'true'
      : 'false';
  }

  if(Array.isArray(value)){
    return esc(
      value.join(', ')
    );
  }

  return esc(value??'—');
}


function resourceFields(res){
  return {
    subdomains:[
      'fqdn',
      'sources',
      'is_new'
    ],

    alive:[
      'url',
      'status_code',
      'title',
      'ip',
      'technologies',
      'waf_name'
    ],

    ips:[
      'ip',
      'hostnames',
      'cdn',
      'cdn_name',
      'waf_name'
    ],

    ports:[
      'ip',
      'port',
      'protocol',
      'service',
      'version',
      'source'
    ],

    endpoints:[
      'url',
      'source',
      'status_code',
      'method',
      'kind'
    ],

    directories:[
      'url',
      'status_code',
      'words',
      'lines',
      'size'
    ],

    technologies:[
      'url',
      'technologies'
    ],

    waf:[
      'url',
      'waf_name'
    ],

    secrets:[
      'source',
      'kind',
      'location',
      'value_masked',
      'severity',
      'verified'
    ],

    findings:[
      'name',
      'tool',
      'severity',
      'target',
      'status'
    ]

  }[res]||[];
}


/*
 * One generic resource table renderer.
 *
 * There are NO dropdown filters here.
 *
 * The column headers themselves are the sorting
 * controls, exactly as requested.
 */
function renderResourceTable(
  host,
  res,
  rows,
  fields,
  extraHeader='',
  extraCell=''
){
  state.resourceRows=
    Array.isArray(rows)
      ? rows
      : [];

  state.resourceRes=res;
  state.resourceHostId=host.id;

  const sorted=[
    ...state.resourceRows
  ];

  if(state.resourceSort.field){
    const field=
      state.resourceSort.field;

    const direction=
      state.resourceSort.direction==='asc'
        ? 1
        : -1;

    sorted.sort(
      (a,b)=>
        compareResourceValues(
          a,
          b,
          field
        )*direction
    );
  }

  host.innerHTML=`
    <div class="table-wrap">

      <table class="table">

        <thead>

          <tr>

            ${fields.map(f=>`
              <th
                role="button"
                tabindex="0"
                onclick="setResourceSort('${f}')"
                onkeydown="
                  if(
                    event.key==='Enter' ||
                    event.key===' '
                  ){
                    event.preventDefault();
                    setResourceSort('${f}')
                  }
                "
                style="
                  cursor:pointer;
                  user-select:none
                "
                title="Sort by ${esc(
                  f.replaceAll('_',' ')
                )}"
              >
                ${esc(
                  f.replaceAll('_',' ')
                )}${sortIndicator(f)}
              </th>
            `).join('')}

            ${extraHeader}

          </tr>

        </thead>

        <tbody>

          ${
            sorted.length

              ? sorted.map(r=>`
                  <tr>

                    ${fields.map(f=>`
                      <td>
                        ${resourceDisplay(
                          r,
                          f,
                          res
                        )}
                      </td>
                    `).join('')}

                    ${
                      extraCell
                        ? extraCell(r)
                        : ''
                    }

                  </tr>
                `).join('')

              : `
                <tr>
                  <td
                    colspan="${
                      fields.length+
                      (extraHeader?1:0)
                    }"
                    class="empty"
                  >
                    No data recorded.
                  </td>
                </tr>
              `
          }

        </tbody>

      </table>

    </div>
  `;
}


function resetResourceTableState(){
  state.resourceRows=[];
  state.resourceRes=null;
  state.resourceHostId=null;

  state.resourceSort={
    field:null,
    direction:'asc'
  };
}


function rerenderCurrentResourceTable(){
  const host=
    state.resourceHostId
      ? $(state.resourceHostId)
      : null;

  if(
    !host||
    !state.resourceRes
  ){
    return;
  }

  const fields=
    resourceFields(
      state.resourceRes
    );

  if(!fields.length){
    return;
  }

  const extraHeader=
    state.resourceRes==='subdomains'
      ? '<th>FFUF</th>'
      : '';

  const extraCell=
    state.resourceRes==='subdomains'
      ? row=>`
          <td>

            <button
              class="btn"
              onclick="openScanFfuf('${esc(row.fqdn||'')}')"
            >
              FFUF
            </button>

          </td>
        `
      : '';

  renderResourceTable(
    host,
    state.resourceRes,
    state.resourceRows,
    fields,
    extraHeader,
    extraCell
  );
}


/* =========================================================
   Dashboard
   ========================================================= */

async function loadDashboard(){
  const el=$('page-dashboard');

  el.innerHTML=
    '<div class="empty"><span class="spinner"></span> Loading dashboard…</div>';

  try{
    const [
      d,
      scans
    ]=await Promise.all([
      api('/api/dashboard'),
      api('/api/scans?limit=8')
    ]);

    const active=
      scans.find(
        s=>[
          'running',
          'stopping',
          'queued'
        ].includes(s.status)
      );

    el.innerHTML=`
      <div class="head">

        <div>

          <h2>
            Surface Overview
          </h2>

          <p>
            Local attack-surface visibility
            driven by PostgreSQL-backed scan results.
          </p>

        </div>

        <span
          class="badge ${active?'cyan':'green'}"
        >
          ${active?'SCAN ACTIVE':'IDLE'}
        </span>

      </div>

      <div class="kpis">

        <div class="kpi">
          <div class="tiny">
            Targets
          </div>

          <div class="v">
            ${d.targets}
          </div>

          <div class="delta">
            canonical target groups
          </div>
        </div>

        <div class="kpi">
          <div class="tiny">
            Subdomains
          </div>

          <div class="v">
            ${d.subdomains}
          </div>

          <div class="delta">
            discovered assets
          </div>
        </div>

        <div class="kpi">
          <div class="tiny">
            Alive Web
          </div>

          <div class="v">
            ${d.alive}
          </div>

          <div class="delta">
            200 · 401 · 403 · 404
          </div>
        </div>

        <div class="kpi">
          <div class="tiny">
            Endpoints
          </div>

          <div class="v">
            ${d.endpoints}
          </div>

          <div class="delta">
            historical + crawled
          </div>
        </div>

        <div class="kpi warn">
          <div class="tiny">
            Findings
          </div>

          <div class="v">
            ${d.findings}
          </div>

          <div class="delta">
            bugs / exposures
          </div>
        </div>

      </div>

      <div class="grid2">

        <div class="card">

          <div class="card-head">

            <h3>
              Current Scan
            </h3>

            <span class="tiny">
              one active scan maximum
            </span>

          </div>

          <div class="card-body">

            ${
              active
                ? `
                  <div class="scan">

                    <div class="scan-top">

                      <div>

                        <div class="scan-title">
                          ${esc(active.target)}
                        </div>

                        <div class="scan-meta">
                          ${esc(active.scan_type)}
                        </div>

                      </div>

                      ${statusBadge(active.status)}

                    </div>

                    <div
                      class="progress"
                      style="margin-top:11px"
                    >
                      <span
                        style="width:${active.progress}%"
                      ></span>
                    </div>

                    <div
                      class="tiny"
                      style="margin-top:7px"
                    >
                      ${esc(
                        active.current_stage||
                        'queued'
                      )}
                      ·
                      ${active.progress}%
                    </div>

                    <div
                      class="actions"
                      style="margin-top:11px"
                    >

                      <button
                        class="btn"
                        onclick="openScan('${active.id}')"
                      >
                        Open Scan
                      </button>

                      ${
                        active.status==='running'||
                        active.status==='stopping'
                          ? `
                            <button
                              class="btn danger"
                              onclick="stopScan('${active.id}')"
                            >
                              Stop Scan
                            </button>
                          `
                          : ''
                      }

                    </div>

                  </div>
                `
                : `
                  <div class="empty">
                    No scan is running.
                    Start a new reconnaissance run.
                  </div>
                `
            }

          </div>

        </div>


        <div class="card">

          <div class="card-head">

            <h3>
              Recent Changes
            </h3>

            <button
              class="btn"
              onclick="openPage('changes')"
            >
              View
            </button>

          </div>

          <div class="card-body">

            ${
              d.recent_changes?.length
                ? `
                  <div class="scan-list">

                    ${d.recent_changes
                      .slice(0,6)
                      .map(c=>`
                        <div class="scan">

                          <div class="scan-top">

                            <strong>
                              ${esc(c.asset)}
                            </strong>

                            <span class="badge green">
                              ${esc(c.type)}
                            </span>

                          </div>

                          <div class="scan-meta">
                            ${esc(c.target)}
                            ·
                            ${esc(c.current||'new')}
                          </div>

                        </div>
                      `)
                      .join('')}

                  </div>
                `
                : `
                  <div class="empty">
                    No recorded changes yet.
                  </div>
                `
            }

          </div>

        </div>

      </div>


      <div
        class="card"
        style="margin-top:16px"
      >

        <div class="card-head">

          <h3>
            Recent Scans
          </h3>

          <button
            class="btn"
            onclick="openPage('scans')"
          >
            All Scans
          </button>

        </div>

        <div class="table-wrap">

          <table class="table">

            <thead>

              <tr>
                <th>Target</th>
                <th>Type</th>
                <th>Status</th>
                <th>Progress</th>
                <th></th>
              </tr>

            </thead>

            <tbody>

              ${
                scans
                  .slice(0,6)
                  .map(s=>`
                    <tr>

                      <td class="mono">
                        ${esc(s.target)}
                      </td>

                      <td>
                        ${esc(s.scan_type)}
                      </td>

                      <td>
                        ${statusDot(s.status)}
                      </td>

                      <td>
                        ${s.progress}%
                      </td>

                      <td>

                        <button
                          class="btn"
                          onclick="openScan('${s.id}')"
                        >
                          Open
                        </button>

                      </td>

                    </tr>
                  `)
                  .join('')
              }

            </tbody>

          </table>

        </div>

      </div>
    `;

    syncHeader();

    if(active){
      startScanStream(active.id)
    }

  }catch(e){
    el.innerHTML=`
      <div class="empty">
        ${esc(hideScanIds(e.message))}
      </div>
    `
  }
}


/* =========================================================
   Scans
   ========================================================= */

async function loadScans(){
  const el=$('page-scans');

  el.innerHTML=
    '<div class="empty"><span class="spinner"></span> Loading scans…</div>';

  try{
    const scans=
      await api('/api/scans?limit=200');

    const active=
      scans.find(
        s=>[
          'queued',
          'running',
          'stopping'
        ].includes(s.status)
      );

    el.innerHTML=`
      <div class="head">

        <div>

          <h2>
            Scans
          </h2>

          <p>
            Active scan, live progress and
            complete scan history in one place.
          </p>

        </div>

        <div class="actions">

          <span
            class="badge ${active?'cyan':'green'}"
          >
            ${active?'1 ACTIVE':'IDLE'}
          </span>

          <button
            class="btn primary"
            onclick="openModal()"
            ${active?'disabled':''}
          >
            ＋ New Scan
          </button>

        </div>

      </div>


      <div
        class="metric-grid"
        style="margin-bottom:16px"
      >

        <div class="metric">
          <strong>
            ${
              scans.filter(
                s=>s.status==='running'
              ).length
            }
          </strong>

          <span>
            Running
          </span>
        </div>

        <div class="metric">
          <strong>
            ${
              scans.filter(
                s=>s.status==='stopping'
              ).length
            }
          </strong>

          <span>
            Stopping
          </span>
        </div>

        <div class="metric">
          <strong>
            ${
              scans.filter(
                s=>terminalStatuses.has(
                  s.status
                )
              ).length
            }
          </strong>

          <span>
            Completed / Stopped
          </span>
        </div>

        <div class="metric">
          <strong>
            1
          </strong>

          <span>
            Max Concurrent
          </span>
        </div>

      </div>


      ${
        active
          ? `
            <div
              class="card"
              style="margin-bottom:16px"
            >

              <div class="card-head">

                <h3>
                  Active Scan
                </h3>

                ${statusBadge(active.status)}

              </div>

              <div class="card-body">

                <div class="scan-top">

                  <div>

                    <div class="scan-title mono">
                      ${esc(active.target)}
                    </div>

                    <div class="scan-meta">
                      ${esc(active.scan_type)}
                    </div>

                  </div>

                  <div class="actions">

                    <button
                      class="btn"
                      onclick="openScan('${active.id}')"
                    >
                      Open
                    </button>

                    ${
                      active.status==='running'||
                      active.status==='stopping'
                        ? `
                          <button
                            class="btn danger"
                            onclick="stopScan('${active.id}')"
                          >
                            Stop Scan
                          </button>
                        `
                        : ''
                    }

                  </div>

                </div>

                <div
                  class="progress"
                  style="margin-top:12px"
                >
                  <span
                    style="width:${active.progress}%"
                  ></span>
                </div>

                <div
                  class="tiny"
                  style="margin-top:7px"
                >
                  ${esc(
                    active.current_stage||
                    'queued'
                  )}
                  ·
                  ${active.progress}%
                </div>

              </div>

            </div>
          `
          : ''
      }


      <div class="card">

        <div class="card-head">

          <h3>
            Scan History
          </h3>

          <div class="tiny">
            ${scans.length} runs
          </div>

        </div>

        <div class="table-wrap">

          <table class="table">

            <thead>

              <tr>
                <th>Target</th>
                <th>Type</th>
                <th>Status</th>
                <th>Progress</th>
                <th>Created</th>
                <th>Finished</th>
                <th>Actions</th>
              </tr>

            </thead>

            <tbody>

              ${
                scans
                  .map(s=>`
                    <tr>

                      <td class="mono">
                        ${esc(s.target)}
                      </td>

                      <td>
                        ${esc(s.scan_type)}
                      </td>

                      <td>
                        ${statusDot(s.status)}
                      </td>

                      <td>
                        ${s.progress}%
                      </td>

                      <td class="muted">
                        ${
                          new Date(
                            s.created_at
                          ).toLocaleString()
                        }
                      </td>

                      <td class="muted">
                        ${
                          s.finished_at
                            ? new Date(
                                s.finished_at
                              ).toLocaleString()
                            : '—'
                        }
                      </td>

                      <td>

                        <button
                          class="btn"
                          onclick="openScan('${s.id}')"
                        >
                          Open
                        </button>

                      </td>

                    </tr>
                  `)
                  .join('')
                ||
                `
                  <tr>
                    <td
                      colspan="7"
                      class="empty"
                    >
                      No scans yet.
                    </td>
                  </tr>
                `
              }

            </tbody>

          </table>

        </div>

      </div>
    `;

    syncHeader();

    if(active){
      startScanStream(active.id)
    }

  }catch(e){
    el.innerHTML=`
      <div class="empty">
        ${esc(hideScanIds(e.message))}
      </div>
    `
  }
}


/* =========================================================
   Assets
   ========================================================= */

function assetTabs(){
  return [
    'subdomains',
    'alive',
    'ports',
    'endpoints',
    'directories',
    'technologies',
    'waf',
    'secrets',
    'findings'
  ]
}

async function getScanResource(id,resource){
  return api(
    `/api/scans/${id}/${resource}`
  )
}

function exportLinks(scanId,res){
  return `
    <div class="actions">

      <a
        class="btn"
        href="/api/scans/${scanId}/export/${res}.json"
      >
        JSON
      </a>

      <a
        class="btn"
        href="/api/scans/${scanId}/export/${res}.txt"
      >
        TXT
      </a>

    </div>
  `
}

async function loadScanDetail(){
  const el=$('page-scan-detail');

  if(!state.scanId){
    openPage('scans');
    return
  }

  el.innerHTML=
    '<div class="empty"><span class="spinner"></span> Loading scan…</div>';

  try{
    const d=
      await api(
        `/api/scans/${state.scanId}`
      );

    state.scan=d;

    resetResourceTableState();

    const stages=d.stages||[];

    const active=
      !terminalStatuses.has(
        d.status
      );

    el.innerHTML=`
      <div class="head">

        <div>

          <h2>
            ${esc(d.target)}
          </h2>

          <p>
            ${esc(d.scan_type)}
            ·
            ${d.links.length}
            submitted link(s)
          </p>

        </div>

        <div class="actions">

          <span
            class="badge ${active?'cyan':'green'}"
          >
            ${esc(
              d.status
                .replaceAll('_',' ')
                .toUpperCase()
            )}
          </span>

          ${
            active
              ? `
                <button
                  class="btn danger"
                  onclick="stopScan('${d.id}')"
                >
                  ⛔ Stop Scan
                </button>
              `
              : ''
          }

          <button
            class="btn"
            onclick="openPage('scans')"
          >
            ← Scans
          </button>

        </div>

      </div>


      <div class="card">

        <div class="card-body">

          <div class="callout">

            <strong>
              Submitted links:
            </strong>

            ${d.links
              .map(
                x=>`
                  <span
                    class="mono"
                    style="margin-right:10px"
                  >
                    ${esc(x)}
                  </span>
                `
              )
              .join('')}

          </div>

          <div
            class="progress"
            style="margin-top:15px"
          >

            <span
              style="width:${d.progress}%"
            ></span>

          </div>

          <div
            class="tiny"
            style="margin-top:7px"
          >
            ${esc(
              d.current_stage||
              'complete'
            )}
            ·
            ${d.progress}%
          </div>

        </div>

      </div>


      <div
        class="card"
        style="margin-top:16px"
      >

        <div class="card-head">

          <h3>
            Pipeline
          </h3>

          <span class="tiny">
            one scan at a time
          </span>

        </div>

        <div class="card-body">

          <div class="scan-list">

            ${stages
              .map(
                s=>`
                  <div class="scan">

                    <div class="scan-top">

                      <strong>
                        ${esc(s.name)}
                      </strong>

                      ${statusBadge(s.status)}

                    </div>

                    <div
                      class="tiny"
                      style="margin-top:7px"
                    >

                      ${s.progress}%

                      ${
                        s.error
                          ? `
                            ·
                            ${esc(
                              hideScanIds(
                                s.error
                              )
                            )}
                          `
                          : ''
                      }

                    </div>

                  </div>
                `
              )
              .join('')}

          </div>

        </div>

      </div>


      <div
        class="tabs"
        style="margin-top:16px"
      >

        ${assetTabs()
          .map(
            x=>`
              <button
                class="tab ${
                  state.assetTab===x
                    ? 'active'
                    : ''
                }"
                onclick="selectAssetTab('${x}')"
              >
                ${x.replaceAll('_',' ')}
              </button>
            `
          )
          .join('')}

      </div>


      <div
        id="assetDetailCard"
        class="card"
      ></div>
    `;

    await renderScanAssetTab();

    if(active){
      startScanStream(d.id)
    }

  }catch(e){
    el.innerHTML=`
      <div class="empty">
        ${esc(hideScanIds(e.message))}
      </div>
    `
  }
}

async function selectAssetTab(tab){
  state.assetTab=tab;

  resetResourceTableState();

  await renderScanAssetTab()
}

async function renderScanAssetTab(){
  const host=$('assetDetailCard');

  if(
    !host||
    !state.scanId
  ){
    return
  }

  host.innerHTML=
    '<div class="empty"><span class="spinner"></span> Loading…</div>';

  const res=state.assetTab;

  try{
    const rows=
      await getScanResource(
        state.scanId,
        res==='findings'
          ? 'findings'
          : res
      );

    const fields=
      resourceFields(res);

    host.innerHTML=`
      <div class="card-head">

        <h3>
          ${
            res==='subdomains'
              ? 'Subdomains'
              : res.replaceAll('_',' ')
          }
        </h3>

        ${exportLinks(
          state.scanId,
          res
        )}

      </div>
    `;

    const tableHost=
      document.createElement('div');

    tableHost.id=
      'scanResourceTable';

    host.appendChild(tableHost);

    const extraHeader=
      res==='subdomains'
        ? '<th>Action</th>'
        : '';

    const extraCell=
      res==='subdomains'
        ? row=>`
            <td>

              <button
                class="btn"
                onclick="openScanFfuf('${esc(row.fqdn||'')}')"
              >
                FFUF
              </button>

            </td>
          `
        : '';

    renderResourceTable(
      tableHost,
      res,
      rows,
      fields,
      extraHeader,
      extraCell
    );

  }catch(e){
    host.innerHTML=`
      <div class="empty">
        ${esc(hideScanIds(e.message))}
      </div>
    `;
  }
}


function openScanFfuf(host){
  if(!state.scanId){
    return
  }

  state.ffufRunId=null;
  state.ffufHost=host;

  openPage('scan-ffuf')
}


/* =========================================================
   FFUF
   ========================================================= */

async function renderFfufPage(){
  const el=$('page-scan-ffuf');

  if(!state.scanId){
    openPage('scans');
    return
  }

  try{
    const scan=
      state.scan||
      await api(
        `/api/scans/${state.scanId}`
      );

    const words=
      await api('/api/wordlists');

    el.innerHTML=`
      <div class="head">

        <div>

          <h2>
            FFUF ·
            <span class="mono">
              ${esc(
                state.ffufHost||
                'Select a subdomain'
              )}
            </span>
          </h2>

          <p>
            Scan-scoped fuzzing.
            Configure exactly what to send
            and inspect actual FFUF output.
          </p>

        </div>

        <div class="actions">

          <button
            class="btn"
            onclick="openPage('scan-detail')"
          >
            ← Back to Scan
          </button>

          <span class="badge cyan">
            SCAN SCOPED
          </span>

        </div>

      </div>


      <div class="grid2">

        <div class="card">

          <div class="card-head">
            <h3>
              Target & Wordlist
            </h3>
          </div>

          <div class="card-body">

            <div class="form-grid">

              <div class="field full">

                <label>
                  Subdomain
                </label>

                <select
                  id="ffufSubdomain"
                  class="select"
                >

                  ${
                    (
                      await getScanResource(
                        state.scanId,
                        'subdomains'
                      )
                    )
                      .map(
                        x=>`
                          <option
                            value="${esc(x.fqdn)}"
                            ${
                              x.fqdn===state.ffufHost
                                ? 'selected'
                                : ''
                            }
                          >
                            ${esc(x.fqdn)}
                          </option>
                        `
                      )
                      .join('')
                  }

                </select>

              </div>


              <div class="field">

                <label>
                  Mode
                </label>

                <select
                  id="ffufMode"
                  class="select"
                >

                  <option value="path">
                    Path / Directory
                  </option>

                  <option value="parameter">
                    Parameter
                  </option>

                  <option value="header">
                    Header
                  </option>

                  <option value="body">
                    Body
                  </option>

                </select>

              </div>


              <div class="field">

                <label>
                  Method
                </label>

                <select
                  id="ffufMethod"
                  class="select"
                >

                  <option>
                    GET
                  </option>

                  <option>
                    POST
                  </option>

                  <option>
                    PUT
                  </option>

                  <option>
                    PATCH
                  </option>

                  <option>
                    DELETE
                  </option>

                </select>

              </div>


              <div class="field full">

                <label>
                  Exact URL / insertion point
                </label>

                <input
                  id="ffufUrl"
                  class="input"
                  value="https://${esc(
                    state.ffufHost||
                    'example.com'
                  )}/FUZZ"
                >

              </div>


              <div class="field">

                <label>
                  SecLists / Custom wordlist
                </label>

                <select
                  id="ffufWordlist"
                  class="select"
                >

                  ${words
                    .map(
                      w=>`
                        <option
                          value="${esc(w.id)}"
                        >
                          ${esc(w.name)}
                        </option>
                      `
                    )
                    .join('')}

                </select>

              </div>


              <div class="field">

                <label>
                  Threads
                </label>

                <input
                  id="ffufThreads"
                  class="input"
                  type="number"
                  min="1"
                  max="100"
                  value="20"
                >

              </div>


              <div class="field">

                <label>
                  Request rate
                </label>

                <input
                  id="ffufRate"
                  class="input"
                  type="number"
                  min="0"
                  value="0"
                >

              </div>


              <div class="field">

                <label>
                  Extensions
                </label>

                <input
                  id="ffufExtensions"
                  class="input"
                  placeholder=".php,.json,.bak"
                >

              </div>

            </div>


            <div
              class="actions"
              style="margin-top:13px"
            >

              <input
                id="customWordlist"
                type="file"
                accept=".txt"
                style="display:none"
              >

              <button
                class="btn"
                onclick="$('customWordlist').click()"
              >
                Upload custom wordlist
              </button>

              <button
                id="uploadWordBtn"
                class="btn"
                style="display:none"
                onclick="uploadCustomWordlist()"
              >
                Save custom wordlist
              </button>

            </div>

          </div>

        </div>


        <div class="card">

          <div class="card-head">
            <h3>
              Match / Filter
            </h3>
          </div>

          <div class="card-body">

            <div class="form-grid">

              <div class="field">

                <label>
                  Match status
                </label>

                <input
                  id="mStatus"
                  class="input"
                  placeholder="200,204,301"
                >

              </div>


              <div class="field">

                <label>
                  Filter status
                </label>

                <input
                  id="fStatus"
                  class="input"
                  placeholder="404"
                >

              </div>


              <div class="field">

                <label>
                  Match size
                </label>

                <input
                  id="mSize"
                  class="input"
                >

              </div>


              <div class="field">

                <label>
                  Filter size
                </label>

                <input
                  id="fSize"
                  class="input"
                >

              </div>


              <div class="field">

                <label>
                  Match words
                </label>

                <input
                  id="mWords"
                  class="input"
                >

              </div>


              <div class="field">

                <label>
                  Filter words
                </label>

                <input
                  id="fWords"
                  class="input"
                >

              </div>


              <div class="field">

                <label>
                  Match lines
                </label>

                <input
                  id="mLines"
                  class="input"
                >

              </div>


              <div class="field">

                <label>
                  Filter lines
                </label>

                <input
                  id="fLines"
                  class="input"
                >

              </div>


              <div class="field full">

                <label>
                  Regex filter
                </label>

                <input
                  id="ffufRegex"
                  class="input"
                >

              </div>


              <div class="field full">

                <label>
                  Headers (one per line: Name: value)
                </label>

                <textarea
                  id="ffufHeaders"
                  class="textarea"
                  style="min-height:70px"
                ></textarea>

              </div>


              <div class="field full">

                <label>
                  Body
                </label>

                <textarea
                  id="ffufBody"
                  class="textarea"
                  style="min-height:70px"
                  placeholder='{"name":"FUZZ"}'
                ></textarea>

              </div>

            </div>


            <button
              class="btn primary"
              style="
                width:100%;
                margin-top:15px
              "
              onclick="startFfuf()"
            >
              ▶ Run FFUF
            </button>

          </div>

        </div>

      </div>


      <div
        class="card"
        style="margin-top:16px"
      >

        <div class="card-head">

          <h3>
            Actual Output
          </h3>

          <div class="actions">

            <span
              id="ffufStatus"
              class="badge"
            >
              READY
            </span>

            <button
              class="btn"
              onclick="clearFfufOutput()"
            >
              Clear
            </button>

          </div>

        </div>

        <div class="card-body">

          <div
            id="ffufOutput"
            class="output"
          >

            <div class="out-line muted">
              Select a target, configure the request and run FFUF.
            </div>

          </div>

        </div>

      </div>
    `;

    const file=$('customWordlist');

    file.onchange=()=>{
      $('uploadWordBtn').style.display=
        file.files.length
          ? 'inline-flex'
          : 'none'
    };

    if(state.ffufRunId){
      attachFfufStream(
        state.ffufRunId
      )
    }

  }catch(e){
    el.innerHTML=`
      <div class="empty">
        ${esc(hideScanIds(e.message))}
      </div>
    `
  }
}

async function uploadCustomWordlist(){
  const f=
    $('customWordlist')
      .files[0];

  if(!f){
    return
  }

  const form=new FormData();

  form.append(
    'file',
    f
  );

  try{
    const r=
      await fetch(
        '/api/wordlists/custom',
        {
          method:'POST',
          body:form
        }
      );

    if(!r.ok){
      throw new Error(
        await r.text()
      );
    }

    toast(
      'Custom wordlist stored in PostgreSQL.'
    );

    renderFfufPage();

  }catch(e){
    toast(e.message)
  }
}

function parseHeaders(text){
  const out={};

  for(
    const line of text.split(/\n/)
  ){
    const i=line.indexOf(':');

    if(i>0){
      out[
        line.slice(0,i).trim()
      ]=
        line.slice(i+1).trim();
    }
  }

  return out;
}

async function startFfuf(){
  try{
    const url=
      $('ffufUrl')
        .value
        .trim();

    const payload={
      scan_id:state.scanId,
      subdomain:$('ffufSubdomain').value,
      mode:$('ffufMode').value,
      url,
      method:$('ffufMethod').value,
      headers:parseHeaders(
        $('ffufHeaders').value
      ),
      body:$('ffufBody').value||null,
      wordlist_id:$('ffufWordlist').value,
      match_status:$('mStatus').value||null,
      filter_status:$('fStatus').value||null,
      match_size:$('mSize').value||null,
      filter_size:$('fSize').value||null,
      match_words:$('mWords').value||null,
      filter_words:$('fWords').value||null,
      match_lines:$('mLines').value||null,
      filter_lines:$('fLines').value||null,
      regex:$('ffufRegex').value||null,
      extensions:$('ffufExtensions').value||null,
      threads:Number(
        $('ffufThreads').value||20
      ),
      rate:Number(
        $('ffufRate').value||0
      ),
      recursion:false
    };

    const run=
      await api(
        '/api/ffuf-runs',
        {
          method:'POST',
          body:JSON.stringify(payload)
        }
      );

    state.ffufRunId=run.id;

    $('ffufStatus').textContent=
      'QUEUED';

    $('ffufOutput').innerHTML=
      '<div class="out-line bluec">[StackSurface] FFUF queued.</div>';

    attachFfufStream(run.id);

    toast('FFUF started.');

  }catch(e){
    toast(e.message)
  }
}

function clearFfufOutput(){
  $('ffufOutput').innerHTML=''
}

function attachFfufStream(runId){
  stopFfufStream();

  const es=
    new EventSource(
      `/api/ffuf-runs/${runId}/stream`
    );

  state.ffufEventSource=es;

  es.onmessage=e=>{
    const d=
      JSON.parse(e.data);

    $('ffufStatus').textContent=
      'RUNNING';

    $('ffufOutput').innerHTML+=`
      <div class="out-line">
        ${esc(d.line)}
      </div>
    `;

    $('ffufOutput').scrollTop=
      $('ffufOutput').scrollHeight;
  };

  es.addEventListener(
    'done',
    e=>{
      const d=
        JSON.parse(e.data);

      $('ffufStatus').textContent=
        d.status.toUpperCase();

      if(d.error){
        $('ffufOutput').innerHTML+=`
          <div class="out-line redc">
            ${esc(d.error)}
          </div>
        `;
      }

      es.close();

      state.ffufEventSource=null
    }
  );

  es.onerror=()=>{
    if($('ffufStatus')){
      $('ffufStatus').textContent=
        'DISCONNECTED'
    }
  }
}


/* =========================================================
   Scan streaming
   ========================================================= */

function startScanStream(id){
  stopScanStream();

  const es=
    new EventSource(
      `/api/scans/${id}/stream`
    );

  state.scanEventSource=es;

  es.onmessage=
    async e=>{
      const d=
        JSON.parse(e.data);

      if(
        state.page==='scan-detail'||
        state.page==='scans'||
        state.page==='dashboard'
      ){
        if(state.scanId===id){
          state.scan=d
        }
      }

      if(
        terminalStatuses.has(
          d.status
        )
      ){
        es.close();

        state.scanEventSource=null;

        if(
          state.page==='scan-detail'
        ){
          await loadScanDetail();
        }else if(
          state.page==='scans'
        ){
          await loadScans();
        }else if(
          state.page==='dashboard'
        ){
          await loadDashboard();
        }else{
          syncHeader()
        }
      }
    };

  es.onerror=()=>{
    if(
      !terminalStatuses.has(
        state.scan?.status||''
      )
    ){
      setTimeout(
        ()=>{
          if(
            [
              'scans',
              'dashboard',
              'scan-detail'
            ].includes(
              state.page
            )
          ){
            startScanStream(id)
          }
        },
        1500
      )
    }
  }
}


/* =========================================================
   Global Assets
   ========================================================= */

async function loadAssets(){
  const scans=
    await api('/api/scans?limit=30');

  const selected=
    state.scanId||
    scans[0]?.id;

  if(!selected){
    $('page-assets').innerHTML=
      '<div class="empty">No scans yet.</div>';

    return
  }

  state.scanId=selected;

  resetResourceTableState();

  const d=
    await api(
      `/api/scans/${selected}`
    );

  $('page-assets').innerHTML=`
    <div class="head">

      <div>

        <h2>
          Assets
        </h2>

        <p>
          Asset columns are persisted per scan.
          FFUF is accessible only from a scan.
        </p>

      </div>

      <span class="badge">
        ${esc(d.target)}
      </span>

    </div>


    <div class="card">

      <div class="card-head">

        <h3>
          Target Group
        </h3>

        <span class="tiny">
          ${d.links.length}
          submitted link(s)
        </span>

      </div>

      <div class="card-body">

        <div class="callout mono">
          ${d.links
            .map(esc)
            .join(' · ')}
        </div>

        <div
          class="metric-grid"
          style="margin-top:14px"
        >

          ${Object.entries(d.counts)
            .map(
              ([k,v])=>`
                <div class="metric">

                  <strong>
                    ${v}
                  </strong>

                  <span>
                    ${k.replaceAll('_',' ')}
                  </span>

                </div>
              `
            )
            .join('')}

        </div>

      </div>

    </div>


    <div
      style="margin-top:16px"
      class="actions"
    >

      <select
        class="select"
        style="max-width:260px"
        onchange="
          state.scanId=this.value;
          loadAssets()
        "
      >

        ${scans
          .map(
            s=>`
              <option
                value="${s.id}"
                ${
                  s.id===selected
                    ? 'selected'
                    : ''
                }
              >
                ${esc(s.target)}
                ·
                ${esc(s.scan_type)}
              </option>
            `
          )
          .join('')}

      </select>


      <button
        class="btn"
        onclick="openScan('${selected}')"
      >
        Open Scan
      </button>

    </div>


    <div
      class="tabs"
      style="margin-top:16px"
    >

      ${assetTabs()
        .map(
          x=>`
            <button
              class="tab ${
                state.assetTab===x
                  ? 'active'
                  : ''
              }"
              onclick="
                selectAssetTabFromAssets(
                  '${x}',
                  '${selected}'
                )
              "
            >
              ${x.replaceAll('_',' ')}
            </button>
          `
        )
        .join('')}

    </div>


    <div
      id="assetGlobalCard"
      class="card"
    ></div>
  `;

  await renderGlobalAssetTab(
    selected
  )
}

async function selectAssetTabFromAssets(
  tab,
  id
){
  state.assetTab=tab;
  state.scanId=id;

  resetResourceTableState();

  await renderGlobalAssetTab(id)
}

async function renderGlobalAssetTab(id){
  const host=$('assetGlobalCard');

  if(!host){
    return
  }

  try{
    const res=
      state.assetTab;

    const rows=
      await getScanResource(
        id,
        res
      );

    const fields=
      resourceFields(res);

    host.innerHTML=`
      <div class="card-head">

        <h3>
          ${res.replaceAll('_',' ')}
        </h3>

        ${exportLinks(
          id,
          res
        )}

      </div>
    `;

    const tableHost=
      document.createElement('div');

    tableHost.id=
      'assetGlobalTable';

    host.appendChild(
      tableHost
    );

    const extraHeader=
      res==='subdomains'
        ? '<th>FFUF</th>'
        : '';

    const extraCell=
      res==='subdomains'
        ? row=>`
            <td>

              <button
                class="btn"
                onclick="
                  state.scanId='${esc(id)}';
                  state.ffufHost='${esc(row.fqdn||'')}';
                  openPage('scan-ffuf')
                "
              >
                FFUF
              </button>

            </td>
          `
        : '';

    renderResourceTable(
      tableHost,
      res,
      rows,
      fields,
      extraHeader,
      extraCell
    );

  }catch(e){
    host.innerHTML=`
      <div class="empty">
        ${esc(hideScanIds(e.message))}
      </div>
    `;
  }
}


/* =========================================================
   Changes
   ========================================================= */

async function loadChanges(){
  const el=$('page-changes');

  const scans=
    await api('/api/scans?limit=30');

  if(!scans.length){
    el.innerHTML=
      '<div class="empty">No scans yet.</div>';

    return
  }

  const selected=
    state.scanId&&
    scans.find(
      s=>s.id===state.scanId
    )
      ? state.scanId
      : scans[0].id;

  state.scanId=selected;

  const d=
    await api(
      `/api/scans/${selected}/changes`
    );

  el.innerHTML=`
    <div class="head">

      <div>

        <h2>
          Changes
        </h2>

        <p>
          Compare the selected scan with
          the previous completed scan for this target.
        </p>

      </div>

      <span class="badge green">
        ${d.length}
        CHANGES
      </span>

    </div>


    <div
      class="actions"
      style="margin-bottom:13px"
    >

      <select
        class="select"
        style="max-width:320px"
        onchange="
          state.scanId=this.value;
          loadChanges()
        "
      >

        ${scans
          .map(
            s=>`
              <option
                value="${s.id}"
                ${
                  s.id===selected
                    ? 'selected'
                    : ''
                }
              >
                ${esc(s.target)}
                ·
                ${esc(s.scan_type)}
              </option>
            `
          )
          .join('')}

      </select>

      ${exportLinks(
        selected,
        'changes'
      )}

    </div>


    <div class="card">

      <div class="table-wrap">

        <table class="table">

          <thead>

            <tr>
              <th>Type</th>
              <th>Asset</th>
              <th>Previous</th>
              <th>Current</th>
            </tr>

          </thead>

          <tbody>

            ${
              d.length
                ? d.map(
                    x=>`
                      <tr>

                        <td>
                          <span class="badge green">
                            ${esc(
                              x.change_type
                            )}
                          </span>
                        </td>

                        <td class="mono">
                          ${esc(x.asset)}
                        </td>

                        <td>
                          ${esc(
                            x.previous_value||
                            '—'
                          )}
                        </td>

                        <td>
                          ${esc(
                            x.current_value||
                            '—'
                          )}
                        </td>

                      </tr>
                    `
                  ).join('')

                : `
                  <tr>

                    <td
                      colspan="4"
                      class="empty"
                    >
                      No changes recorded
                      for this scan.
                    </td>

                  </tr>
                `
            }

          </tbody>

        </table>

      </div>

    </div>
  `
}


/* =========================================================
   Findings
   ========================================================= */

async function loadFindings(){
  const el=$('page-findings');

  const scans=
    await api('/api/scans?limit=30');

  if(!scans.length){
    el.innerHTML=
      '<div class="empty">No scans yet.</div>';

    return
  }

  const selected=
    state.scanId&&
    scans.find(
      s=>s.id===state.scanId
    )
      ? state.scanId
      : scans[0].id;

  state.scanId=selected;

  const rows=
    await api(
      `/api/scans/${selected}/findings`
    );

  el.innerHTML=`
    <div class="head">

      <div>

        <h2>
          Findings
        </h2>

        <p>
          Finding names are kept simple;
          evidence remains in the tool result data.
        </p>

      </div>

      <span class="badge red">
        ${rows.length}
        FINDINGS
      </span>

    </div>


    <div
      class="actions"
      style="margin-bottom:13px"
    >

      <select
        class="select"
        style="max-width:320px"
        onchange="
          state.scanId=this.value;
          loadFindings()
        "
      >

        ${scans
          .map(
            s=>`
              <option
                value="${s.id}"
                ${
                  s.id===selected
                    ? 'selected'
                    : ''
                }
              >
                ${esc(s.target)}
                ·
                ${esc(s.scan_type)}
              </option>
            `
          )
          .join('')}

      </select>

      ${exportLinks(
        selected,
        'findings'
      )}

    </div>


    <div class="card">

      <div class="table-wrap">

        <table class="table">

          <thead>

            <tr>
              <th>Name</th>
              <th>Tool</th>
              <th>Severity</th>
              <th>Target</th>
              <th>Status</th>
            </tr>

          </thead>

          <tbody>

            ${
              rows.length
                ? rows.map(
                    x=>`
                      <tr>

                        <td>
                          ${esc(x.name)}
                        </td>

                        <td>
                          ${esc(x.tool)}
                        </td>

                        <td>
                          ${esc(
                            x.severity||
                            '—'
                          )}
                        </td>

                        <td class="mono">
                          ${esc(
                            x.target||
                            '—'
                          )}
                        </td>

                        <td>
                          ${esc(
                            x.status||
                            'open'
                          )}
                        </td>

                      </tr>
                    `
                  ).join('')

                : `
                  <tr>

                    <td
                      colspan="5"
                      class="empty"
                    >
                      No findings recorded.
                    </td>

                  </tr>
                `
            }

          </tbody>

        </table>

      </div>

    </div>
  `
}


/* =========================================================
   Navigation / Startup
   ========================================================= */

document
  .querySelectorAll('#nav button')
  .forEach(
    b=>
      b.addEventListener(
        'click',
        ()=>openPage(
          b.dataset.page
        )
      )
  );

$('globalSearch').addEventListener(
  'keydown',
  e=>{
    if(e.key==='Enter'){

      const q=
        e.target.value
          .trim()
          .toLowerCase();

      if(!q){
        return
      }

      loadScans().then(
        ()=>openPage('scans')
      );
    }
  }
);

profileSelect('full');

refreshHealth();

openPage('dashboard');

setInterval(
  refreshHealth,
  10000
);

setInterval(
  syncHeader,
  5000
);