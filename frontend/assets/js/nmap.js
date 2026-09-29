(function(){

  const NMAP_PAGE = "scan-nmap";

  const nmapState = {
    runId: null,
    timer: null,
    runs: [],
    scan: null,
    loading: false
  };


  function nesc(value){
    return String(value ?? "").replace(
      /[&<>'"]/g,
      c => ({
        "&":"&amp;",
        "<":"&lt;",
        ">":"&gt;",
        "'":"&#39;",
        '"':"&quot;"
      }[c])
    );
  }


  function nmapToast(message){
    if(typeof toast === "function"){
      toast(message);
    }
  }


  async function nmapApi(url, options = {}){
    const response = await fetch(
      url,
      {
        headers:{
          "Content-Type":"application/json",
          ...(options.headers || {})
        },
        ...options
      }
    );

    let data = null;

    try{
      data = await response.json();
    }catch{}

    if(!response.ok){
      const detail =
        data?.detail ||
        data?.message ||
        `Request failed (${response.status})`;

      throw new Error(
        typeof detail === "string"
          ? detail
          : JSON.stringify(detail)
      );
    }

    return data;
  }


  function selectedConfig(){

    const scripts =
      document.getElementById("nmapScripts")?.value
      ?.trim() || "";

    return {
      scan_type:
        document.getElementById("nmapScanType")?.value
        || "syn",

      port_mode:
        document.getElementById("nmapPortMode")?.value
        || "top",

      top_ports:
        Number(
          document.getElementById("nmapTopPorts")?.value
          || 1000
        ),

      ports:
        document.getElementById("nmapPorts")?.value
        ?.trim() || "",

      host_discovery:
        document.getElementById("nmapHostDiscovery")?.checked
        ?? true,

      service_detection:
        document.getElementById("nmapServiceDetection")?.checked
        ?? true,

      version_intensity:
        Number(
          document.getElementById("nmapVersionIntensity")?.value
          || 7
        ),

      os_detection:
        document.getElementById("nmapOsDetection")?.checked
        ?? false,

      default_scripts:
        document.getElementById("nmapDefaultScripts")?.checked
        ?? false,

      scripts,

      timing:
        Number(
          document.getElementById("nmapTiming")?.value
          || 3
        ),

      ipv6:
        document.getElementById("nmapIPv6")?.checked
        ?? false,

      no_dns:
        document.getElementById("nmapNoDns")?.checked
        ?? false,

      resolve_all:
        document.getElementById("nmapResolveAll")?.checked
        ?? false,

      reason:
        document.getElementById("nmapReason")?.checked
        ?? true,

      traceroute:
        document.getElementById("nmapTraceroute")?.checked
        ?? false,

      open_only:
        document.getElementById("nmapOpenOnly")?.checked
        ?? true,

      verbose:
        Number(
          document.getElementById("nmapVerbose")?.value
          || 1
        ),

      max_retries:
        Number(
          document.getElementById("nmapMaxRetries")?.value
          || 0
        ),

      min_rate:
        document.getElementById("nmapMinRate")?.value
        ?.trim() || "",

      max_rate:
        document.getElementById("nmapMaxRate")?.value
        ?.trim() || "",

      host_timeout:
        document.getElementById("nmapHostTimeout")?.value
        ?.trim() || "",

      scan_delay:
        document.getElementById("nmapScanDelay")?.value
        ?.trim() || "",

      max_scan_delay:
        document.getElementById("nmapMaxScanDelay")?.value
        ?.trim() || ""
    };
  }


  function targetValue(){
    return (
      document.getElementById("nmapTarget")
        ?.value
        ?.trim() || ""
    );
  }


  function renderCommandPreview(){

    const target = targetValue();

    const config = selectedConfig();

    const parts = ["nmap"];

    const scanMap = {
      syn:"-sS",
      connect:"-sT",
      udp:"-sU",
      tcp_udp:"-sS -sU",
      ack:"-sA",
      window:"-sW",
      fin:"-sF",
      null:"-sN",
      xmas:"-sX",
      maimon:"-sM"
    };

    if(scanMap[config.scan_type]){
      parts.push(
        scanMap[config.scan_type]
      );
    }

    if(config.port_mode === "all"){
      parts.push("-p-");
    }else if(config.port_mode === "top"){
      parts.push(
        `--top-ports ${config.top_ports}`
      );
    }else if(config.port_mode === "custom" && config.ports){
      parts.push(
        `-p ${config.ports}`
      );
    }

    if(!config.host_discovery){
      parts.push("-Pn");
    }

    if(config.service_detection){
      parts.push(
        `-sV --version-intensity ${config.version_intensity}`
      );
    }

    if(config.os_detection){
      parts.push("-O");
    }

    if(config.default_scripts){
      parts.push("-sC");
    }

    if(config.scripts){
      parts.push(
        `--script ${config.scripts}`
      );
    }

    parts.push(`-T${config.timing}`);

    if(config.ipv6){
      parts.push("-6");
    }

    if(config.no_dns){
      parts.push("-n");
    }

    if(config.resolve_all){
      parts.push("--resolve-all");
    }

    if(config.reason){
      parts.push("--reason");
    }

    if(config.traceroute){
      parts.push("--traceroute");
    }

    if(config.open_only){
      parts.push("--open");
    }

    if(config.max_retries){
      parts.push(
        `--max-retries ${config.max_retries}`
      );
    }

    if(config.min_rate){
      parts.push(
        `--min-rate ${config.min_rate}`
      );
    }

    if(config.max_rate){
      parts.push(
        `--max-rate ${config.max_rate}`
      );
    }

    if(target){
      parts.push(target);
    }else{
      parts.push("<target>");
    }

    const el =
      document.getElementById(
        "nmapCommandPreview"
      );

    if(el){
      el.textContent =
        parts.join(" ");
    }
  }


  function statusBadge(status){

    const colors = {
      queued:"yellow",
      running:"cyan",
      stopping:"yellow",
      completed:"green",
      failed:"red",
      cancelled:"gray"
    };

    return `
      <span class="badge ${colors[status] || "gray"}">
        ${nesc(
          String(status || "")
            .replaceAll("_"," ")
            .toUpperCase()
        )}
      </span>
    `;
  }


  function renderResults(data){

    const results =
      Array.isArray(data?.results)
        ? data.results
        : [];

    const ports =
      Array.isArray(data?.ports)
        ? data.ports
        : [];

    const resultsEl =
      document.getElementById(
        "nmapResults"
      );

    if(!resultsEl){
      return;
    }

    if(!results.length){
      resultsEl.innerHTML =
        `<div class="empty">No parsed ports yet.</div>`;

      return;
    }

    resultsEl.innerHTML = `
      <div class="table-wrap">
        <table class="table">
          <thead>
            <tr>
              <th>IP</th>
              <th>Port</th>
              <th>Protocol</th>
              <th>State</th>
              <th>Service</th>
              <th>Version</th>
              <th>Reason</th>
            </tr>
          </thead>
          <tbody>
            ${
              results.map(
                x => `
                  <tr>
                    <td class="mono">
                      ${nesc(x.ip || x.hostname || "—")}
                    </td>

                    <td class="mono">
                      ${nesc(x.port)}
                    </td>

                    <td>
                      ${nesc(x.protocol)}
                    </td>

                    <td>
                      <span class="badge green">
                        ${nesc(x.state)}
                      </span>
                    </td>

                    <td>
                      ${nesc(x.service || "unknown")}
                    </td>

                    <td>
                      ${nesc(x.version || "—")}
                    </td>

                    <td class="muted">
                      ${nesc(x.reason || "—")}
                    </td>
                  </tr>
                `
              ).join("")
            }
          </tbody>
        </table>
      </div>
    `;

    const countEl =
      document.getElementById(
        "nmapPortCount"
      );

    if(countEl){
      countEl.textContent =
        String(ports.length);
    }
  }


  function renderRuns(){

    const el =
      document.getElementById(
        "nmapRunHistory"
      );

    if(!el){
      return;
    }

    if(!nmapState.runs.length){
      el.innerHTML =
        `<div class="empty">No Nmap runs for this scan.</div>`;

      return;
    }

    el.innerHTML = `
      <div class="scan-list">
        ${
          nmapState.runs.map(
            run => `
              <button
                class="nmap-run-row"
                onclick="loadNmapRun('${nesc(run.id)}')"
              >
                <span>
                  <strong>
                    ${nesc(run.target)}
                  </strong>

                  <small>
                    ${nesc(
                      run.created_at || ""
                    )}
                  </small>
                </span>

                ${statusBadge(run.status)}
              </button>
            `
          ).join("")
        }
      </div>
    `;
  }


  async function loadNmapRuns(){

    if(!state.scanId){
      nmapState.runs = [];
      renderRuns();
      return;
    }

    try{
      nmapState.runs =
        await nmapApi(
          `/api/scans/${state.scanId}/nmap-runs`
        );

      renderRuns();

    }catch(error){
      nmapToast(error.message);
    }
  }


  async function loadNmapRun(runId){

    try{

      const data =
        await nmapApi(
          `/api/nmap-runs/${runId}`
        );

      nmapState.runId = runId;

      renderNmapRun(data);

      if(
        ["queued","running","stopping"]
          .includes(data.status)
      ){
        startNmapPolling(runId);
      }else{
        stopNmapPolling();
      }

    }catch(error){
      nmapToast(error.message);
    }
  }


  function renderNmapRun(data){

    const status =
      document.getElementById(
        "nmapStatus"
      );

    if(status){
      status.innerHTML =
        statusBadge(data.status);
    }

    const command =
      document.getElementById(
        "nmapCommandResult"
      );

    if(command){
      command.textContent =
        data.command || "—";
    }

    const output =
      document.getElementById(
        "nmapOutput"
      );

    if(output){
      output.textContent =
        data.output || "";
    }

    renderResults(data);

    const error =
      document.getElementById(
        "nmapError"
      );

    if(error){
      error.textContent =
        data.error || "";
    }

    const stopBtn =
      document.getElementById(
        "nmapStopBtn"
      );

    if(stopBtn){

      const active = [
        "queued",
        "running",
        "stopping"
      ].includes(data.status);

      stopBtn.style.display =
        active
          ? "inline-flex"
          : "none";

      stopBtn.disabled =
        data.status === "stopping";
    }
  }


  function startNmapPolling(runId){

    stopNmapPolling();

    nmapState.timer =
      setInterval(
        () => loadNmapRun(runId),
        1000
      );
  }


  function stopNmapPolling(){

    if(nmapState.timer){
      clearInterval(
        nmapState.timer
      );

      nmapState.timer = null;
    }
  }


  async function startNmap(){

    if(!state.scanId){
      nmapToast(
        "Open a scan first, then launch Nmap."
      );
      return;
    }

    const target =
      targetValue();

    if(!target){
      nmapToast(
        "Enter an Nmap target."
      );
      return;
    }

    const button =
      document.getElementById(
        "nmapStartBtn"
      );

    if(button){
      button.disabled = true;
      button.textContent = "Starting…";
    }

    try{

      const run =
        await nmapApi(
          "/api/nmap-runs",
          {
            method:"POST",
            body:JSON.stringify({
              scan_id:state.scanId,
              target,
              config:selectedConfig()
            })
          }
        );

      nmapState.runId =
        run.id;

      nmapToast(
        "Nmap queued."
      );

      await loadNmapRuns();

      await loadNmapRun(
        run.id
      );

    }catch(error){

      nmapToast(
        error.message
      );

    }finally{

      if(button){
        button.disabled = false;
        button.textContent = "Start Nmap";
      }
    }
  }


  async function stopNmap(){

    if(!nmapState.runId){
      return;
    }

    try{

      await nmapApi(
        `/api/nmap-runs/${nmapState.runId}/stop`,
        {
          method:"POST"
        }
      );

      nmapToast(
        "Nmap stop requested."
      );

      await loadNmapRun(
        nmapState.runId
      );

    }catch(error){

      nmapToast(
        error.message
      );
    }
  }


  function setNmapEvents(){

    [
      "nmapTarget",
      "nmapPortMode",
      "nmapTopPorts",
      "nmapPorts",
      "nmapScanType",
      "nmapVersionIntensity",
      "nmapScripts",
      "nmapTiming",
      "nmapMinRate",
      "nmapMaxRate",
      "nmapHostTimeout",
      "nmapScanDelay",
      "nmapMaxScanDelay",
      "nmapVerbose"
    ].forEach(
      id => {

        const el =
          document.getElementById(id);

        if(el){
          el.addEventListener(
            "input",
            renderCommandPreview
          );

          el.addEventListener(
            "change",
            renderCommandPreview
          );
        }
      }
    );

    [
      "nmapHostDiscovery",
      "nmapServiceDetection",
      "nmapOsDetection",
      "nmapDefaultScripts",
      "nmapIPv6",
      "nmapNoDns",
      "nmapResolveAll",
      "nmapReason",
      "nmapTraceroute",
      "nmapOpenOnly"
    ].forEach(
      id => {

        const el =
          document.getElementById(id);

        if(el){
          el.addEventListener(
            "change",
            renderCommandPreview
          );
        }
      }
    );

    const portMode =
      document.getElementById(
        "nmapPortMode"
      );

    if(portMode){
      portMode.addEventListener(
        "change",
        () => {

          const custom =
            portMode.value === "custom";

          document
            .getElementById(
              "nmapCustomPorts"
            )
            ?.classList.toggle(
              "hidden",
              !custom
            );

          const top =
            portMode.value === "top";

          document
            .getElementById(
              "nmapTopPortsWrap"
            )
            ?.classList.toggle(
              "hidden",
              !top
            );

          renderCommandPreview();
        }
      );
    }
  }


  function renderNmapPage(){

    const page =
      document.getElementById(
        "page-scan-nmap"
      );

    if(!page){
      return;
    }

    stopNmapPolling();

    page.innerHTML = `
      <div class="head">
        <div>
          <h2>Nmap</h2>
          <p>
            Network discovery, port enumeration and service intelligence.
          </p>
        </div>

        <div class="actions">
          <button
            class="btn"
            onclick="loadNmapRuns()"
          >
            Refresh
          </button>

          <button
            id="nmapStopBtn"
            class="btn danger"
            style="display:none"
            onclick="stopNmap()"
          >
            Stop Nmap
          </button>

          <button
            id="nmapStartBtn"
            class="btn primary"
            onclick="startNmap()"
          >
            Start Nmap
          </button>
        </div>
      </div>

      ${
        !state.scanId
          ? `
            <div class="callout">
              Open an existing scan first. Nmap runs are
              intentionally scoped to that scan's target.
            </div>
          `
          : `
            <div class="nmap-layout">

              <div class="card">
                <div class="card-head">
                  <h3>Scan Configuration</h3>
                  <span class="badge cyan">
                    ${nesc(
                      state.scan?.target || "Selected scan"
                    )}
                  </span>
                </div>

                <div class="card-body">

                  <div class="form-grid">

                    <div class="field full">
                      <label>Target</label>
                      <input
                        id="nmapTarget"
                        class="input"
                        placeholder="api.example.com"
                        value="${nesc(
                          state.scan?.target || ""
                        )}"
                      >
                    </div>

                    <div class="field">
                      <label>Scan Technique</label>

                      <select
                        id="nmapScanType"
                        class="select"
                      >
                        <option value="syn">
                          TCP SYN (-sS)
                        </option>

                        <option value="connect">
                          TCP Connect (-sT)
                        </option>

                        <option value="udp">
                          UDP (-sU)
                        </option>

                        <option value="tcp_udp">
                          TCP + UDP
                        </option>

                        <option value="ack">
                          TCP ACK (-sA)
                        </option>

                        <option value="window">
                          TCP Window (-sW)
                        </option>

                        <option value="fin">
                          TCP FIN (-sF)
                        </option>

                        <option value="null">
                          TCP NULL (-sN)
                        </option>

                        <option value="xmas">
                          TCP Xmas (-sX)
                        </option>

                        <option value="maimon">
                          TCP Maimon (-sM)
                        </option>
                      </select>
                    </div>

                    <div class="field">
                      <label>Port Selection</label>

                      <select
                        id="nmapPortMode"
                        class="select"
                      >
                        <option value="default">
                          Nmap default
                        </option>

                        <option value="top" selected>
                          Top ports
                        </option>

                        <option value="custom">
                          Custom ports
                        </option>

                        <option value="all">
                          All ports (-p-)
                        </option>
                      </select>
                    </div>

                    <div
                      id="nmapTopPortsWrap"
                      class="field"
                    >
                      <label>Top Ports</label>

                      <input
                        id="nmapTopPorts"
                        class="input"
                        type="number"
                        min="1"
                        max="65535"
                        value="1000"
                      >
                    </div>

                    <div
                      id="nmapCustomPorts"
                      class="field hidden"
                    >
                      <label>Custom Ports</label>

                      <input
                        id="nmapPorts"
                        class="input"
                        placeholder="22,80,443,8000-9000"
                      >
                    </div>

                    <div class="field">
                      <label>Timing Template</label>

                      <select
                        id="nmapTiming"
                        class="select"
                      >
                        <option value="0">T0 · Paranoid</option>
                        <option value="1">T1 · Sneaky</option>
                        <option value="2">T2 · Polite</option>
                        <option value="3" selected>T3 · Normal</option>
                        <option value="4">T4 · Aggressive</option>
                        <option value="5">T5 · Insane</option>
                      </select>
                    </div>

                    <div class="field">
                      <label>Version Intensity</label>

                      <input
                        id="nmapVersionIntensity"
                        class="input"
                        type="number"
                        min="0"
                        max="9"
                        value="7"
                      >
                    </div>

                  </div>

                  <div class="nmap-option-grid">

                    <label class="nmap-check">
                      <input
                        id="nmapHostDiscovery"
                        type="checkbox"
                        checked
                      >
                      <span>
                        Host discovery
                      </span>
                    </label>

                    <label class="nmap-check">
                      <input
                        id="nmapServiceDetection"
                        type="checkbox"
                        checked
                      >
                      <span>
                        Service / version detection
                      </span>
                    </label>

                    <label class="nmap-check">
                      <input
                        id="nmapOsDetection"
                        type="checkbox"
                      >
                      <span>
                        OS detection
                      </span>
                    </label>

                    <label class="nmap-check">
                      <input
                        id="nmapDefaultScripts"
                        type="checkbox"
                      >
                      <span>
                        Default NSE scripts
                      </span>
                    </label>

                    <label class="nmap-check">
                      <input
                        id="nmapIPv6"
                        type="checkbox"
                      >
                      <span>
                        IPv6
                      </span>
                    </label>

                    <label class="nmap-check">
                      <input
                        id="nmapNoDns"
                        type="checkbox"
                      >
                      <span>
                        Disable reverse DNS
                      </span>
                    </label>

                    <label class="nmap-check">
                      <input
                        id="nmapResolveAll"
                        type="checkbox"
                      >
                      <span>
                        Resolve all addresses
                      </span>
                    </label>

                    <label class="nmap-check">
                      <input
                        id="nmapReason"
                        type="checkbox"
                        checked
                      >
                      <span>
                        Show port reasons
                      </span>
                    </label>

                    <label class="nmap-check">
                      <input
                        id="nmapTraceroute"
                        type="checkbox"
                      >
                      <span>
                        Traceroute
                      </span>
                    </label>

                    <label class="nmap-check">
                      <input
                        id="nmapOpenOnly"
                        type="checkbox"
                        checked
                      >
                      <span>
                        Open ports only
                      </span>
                    </label>

                  </div>

                  <div class="field nmap-script-field">
                    <label>
                      NSE Scripts / Categories
                    </label>

                    <input
                      id="nmapScripts"
                      class="input"
                      placeholder="safe,discovery or http-title,ssl-cert"
                    >

                    <span class="tiny">
                      StackSurface blocks the unrestricted
                      <code>all</code> NSE selection.
                    </span>
                  </div>

                  <div class="nmap-advanced">

                    <div class="field">
                      <label>Verbosity</label>

                      <select
                        id="nmapVerbose"
                        class="select"
                      >
                        <option value="0">Normal</option>
                        <option value="1" selected>-v</option>
                        <option value="2">-vv</option>
                        <option value="3">-vvv</option>
                      </select>
                    </div>

                    <div class="field">
                      <label>Max Retries</label>

                      <input
                        id="nmapMaxRetries"
                        class="input"
                        type="number"
                        min="0"
                        max="20"
                        value="0"
                      >
                    </div>

                    <div class="field">
                      <label>Min Rate</label>

                      <input
                        id="nmapMinRate"
                        class="input"
                        placeholder="packets/sec"
                      >
                    </div>

                    <div class="field">
                      <label>Max Rate</label>

                      <input
                        id="nmapMaxRate"
                        class="input"
                        placeholder="packets/sec"
                      >
                    </div>

                    <div class="field">
                      <label>Host Timeout</label>

                      <input
                        id="nmapHostTimeout"
                        class="input"
                        placeholder="30s / 5m"
                      >
                    </div>

                    <div class="field">
                      <label>Scan Delay</label>

                      <input
                        id="nmapScanDelay"
                        class="input"
                        placeholder="100ms / 1s"
                      >
                    </div>

                    <div class="field">
                      <label>Max Scan Delay</label>

                      <input
                        id="nmapMaxScanDelay"
                        class="input"
                        placeholder="1s"
                      >
                    </div>

                  </div>

                  <div class="nmap-command-card">
                    <div class="tiny">
                      GENERATED COMMAND
                    </div>

                    <pre
                      id="nmapCommandPreview"
                      class="nmap-command"
                    >nmap -sS --top-ports 1000 -sV -T3 --open &lt;target&gt;</pre>
                  </div>

                </div>
              </div>

              <div class="card">

                <div class="card-head">
                  <h3>Nmap Run</h3>

                  <span
                    id="nmapStatus"
                    class="badge gray"
                  >
                    READY
                  </span>
                </div>

                <div class="card-body">

                  <div class="metric-grid">

                    <div class="metric">
                      <strong
                        id="nmapPortCount"
                      >
                        0
                      </strong>
                      <span>
                        Ports
                      </span>
                    </div>

                    <div class="metric">
                      <strong>
                        Nmap
                      </strong>
                      <span>
                        Source
                      </span>
                    </div>

                    <div class="metric">
                      <strong>
                        XML
                      </strong>
                      <span>
                        Parser
                      </span>
                    </div>

                    <div class="metric">
                      <strong>
                        DB
                      </strong>
                      <span>
                        Persisted
                      </span>
                    </div>

                  </div>

                  <div class="nmap-section-title">
                    Command
                  </div>

                  <pre
                    id="nmapCommandResult"
                    class="nmap-command"
                  >—</pre>

                  <div class="nmap-section-title">
                    Parsed Results
                  </div>

                  <div id="nmapResults">
                    <div class="empty">
                      Start an Nmap run.
                    </div>
                  </div>

                  <div class="nmap-section-title">
                    Output
                  </div>

                  <pre
                    id="nmapOutput"
                    class="output nmap-output"
                  ></pre>

                  <div
                    id="nmapError"
                    class="nmap-error"
                  ></div>

                </div>
              </div>

            </div>

            <div class="card nmap-history-card">

              <div class="card-head">
                <h3>Nmap History</h3>

                <span class="tiny">
                  Current scan
                </span>
              </div>

              <div class="card-body">
                <div id="nmapRunHistory">
                  <div class="empty">
                    Loading…
                  </div>
                </div>
              </div>

            </div>
          `
      }
    `;

    setNmapEvents();

    renderCommandPreview();

    loadNmapRuns();

    if(nmapState.runId){
      loadNmapRun(
        nmapState.runId
      );
    }
  }


  // ----------------------------------------------------------
  // Integrate with existing StackSurface navigation.
  // ----------------------------------------------------------

  if(
    typeof VALID_PAGES !== "undefined"
    && VALID_PAGES instanceof Set
  ){
    VALID_PAGES.add(
      NMAP_PAGE
    );
  }


  const originalRenderPage =
    window.renderPage;

  window.renderPage =
    function(){

      if(
        state.page === NMAP_PAGE
      ){
        renderNmapPage();
        return;
      }

      if(
        typeof originalRenderPage === "function"
      ){
        originalRenderPage();
      }
    };


  window.renderNmapPage =
    renderNmapPage;

  window.startNmap =
    startNmap;

  window.stopNmap =
    stopNmap;

  window.loadNmapRuns =
    loadNmapRuns;

  window.loadNmapRun =
    loadNmapRun;


  // If navigation state was restored to Nmap,
  // render it after this module loads.
  if(
    typeof state !== "undefined"
    && state.page === NMAP_PAGE
  ){
    renderNmapPage();
  }

})();
