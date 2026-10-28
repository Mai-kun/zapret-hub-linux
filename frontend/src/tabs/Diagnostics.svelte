<script lang="ts" module>
  import type { DoctorReport } from "$lib/ipc/bindings";

  /** The last report in memory: the tab opens on it at once and refreshes in the background. */
  let last: DoctorReport | null = null;
</script>

<script lang="ts">
  import { commands, type CheckStatus, type DiagnosticTarget, type FixAction, type ProbeResult, type ServiceDiagnosticsReport } from "$lib/ipc/bindings";
  import { call } from "$lib/api";
  import { app, change } from "$lib/app.svelte";
  import { S } from "$lib/strings";

  let report = $state(last);
  let checking = $state(false);
  let target = $state("");
  let result = $state<ProbeResult | null>(null);
  let probeBusy = $state(false);
  let serviceReport = $state<ServiceDiagnosticsReport | null>(null);
  let serviceBusy = $state<DiagnosticTarget | null>(null);

  /** The quick targets of the Probe block: chip label → what is probed. */
  const CHIPS: Array<[string, string]> = [
    [S.diagnostics.probe.chips.discord, "discord.com"],
    [S.diagnostics.probe.chips.discordGateway, "https://gateway.discord.gg"],
    [S.diagnostics.probe.chips.youtube, "https://www.youtube.com"],
    [S.diagnostics.probe.chips.youtubeVideo, "https://www.youtube.com/watch?v=dQw4w9WgXcQ"],
    [S.diagnostics.probe.chips.steam, "store.steampowered.com"],
    [S.diagnostics.probe.chips.telegramWeb, "web.telegram.org"],
  ];

  async function doctor(): Promise<void> {
    checking = true;
    try {
      report = (await call(S.failed.doctor, commands.doctor())) ?? report;
    } finally {
      checking = false;
    }
  }

  async function fix(action: FixAction): Promise<void> {
    report = (await change(S.failed.fix, () => commands.fixDoctorIssue(action))) ?? report;
  }

  async function fixAll(): Promise<void> {
    report = (await change(S.failed.fixAll, () => commands.fixAllDoctorIssues())) ?? report;
  }

  async function probe(what?: string): Promise<void> {
    const subject = (what ?? target).trim();
    if (!subject) return;
    probeBusy = true;
    try {
      result = (await call(S.failed.doctor, commands.probe(subject))) ?? result;
      target = subject;
    } finally {
      probeBusy = false;
    }
  }

  /** The deep diagnosis of one service's real traffic: voice UDP, WebSocket, a video chunk. */
  async function diagnoseService(service: DiagnosticTarget): Promise<void> {
    serviceBusy = service;
    try {
      serviceReport =
        (await call(S.failed.doctor, commands.diagnoseService(service))) ?? serviceReport;
    } finally {
      serviceBusy = null;
    }
  }

  /** The one line the checks add up to; the statuses of curl decide (probe spec). */
  function summary(p: ProbeResult): string {
    if (!p.resolved_ips.length) return S.diagnostics.probe.summary.dnsMiss;
    if (p.matching.excluded_domain || p.matching.excluded_ip)
      return S.diagnostics.probe.summary.excluded;
    const ok = (status: CheckStatus) => status === "Ok";
    const { http, tls12, tls13 } = p.checks;
    if (ok(http.status) && ok(tls12.status) && ok(tls13.status))
      return S.diagnostics.probe.summary.allOk;
    if (ok(http.status) && ok(tls12.status)) return S.diagnostics.probe.summary.tls13Only;
    if (ok(http.status)) return S.diagnostics.probe.summary.tlsFail;
    if (p.checks.ping_ms) return S.diagnostics.probe.summary.pingOnly;
    return S.diagnostics.probe.summary.nothing;
  }

  type Cell = { label: string; value: string; tone: "ok" | "warn" | "bad" };
  function cells(report: DoctorReport): Cell[] {
    const d = S.diagnostics.checkpoints;
    const bins = report.lists_and_bins.bins;
    const emptyBins = bins.filter((bin) => bin.bytes === 0).length;
    const conflicts = report.conflicts.processes.length + report.conflicts.tables.length;
    const tg = report.proxies.tg_ws;
    const socks = report.proxies.socks5;
    // A Windows build has no caps to check (`engine_diag` says each of them).
    const isExeBuild = (report.engine.path ?? "").endsWith(".exe");
    const engineOk =
      !!report.engine.path &&
      report.engine.executable &&
      (isExeBuild || (report.engine.cap_net_admin && report.engine.cap_net_raw));
    const engine: Cell = report.engine.path
      ? {
          label: d.engine,
          value:
            `${report.engine.error ?? report.engine.version ?? d.noVersion}` +
            (isExeBuild ? "" : `; права: ${report.engine.cap_net_admin && report.engine.cap_net_raw ? "на месте" : "нет"}`),
          tone: engineOk && report.engine.version ? "ok" : "bad",
        }
      : { label: d.engine, value: d.noEngine, tone: "bad" };
    const cells: Cell[] = [
      {
        label: d.systemDns,
        value: report.system_dns.system_ok
          ? d.systemOk
          : report.system_dns.direct_ok
            ? d.systemBroken
            : d.systemDown,
        tone: report.system_dns.system_ok ? "ok" : report.system_dns.direct_ok ? "bad" : "warn",
      },
      engine,
      {
        label: d.service,
        value:
          report.service.state === "Running" && report.nfqueue.open
            ? `работает (pid по очереди ${report.nfqueue.peer_portid ?? "—" }), пакетов в очереди: ${report.nfqueue.queue_total ?? 0}`
            : `${S.svc[report.service.state]}${report.nfqueue.open ? ", очередь открыта" : ""}`,
        tone: report.service.state === "Running" && report.nfqueue.open ? "ok" : "bad",
      },
      {
        label: d.nft,
        value: d.nftHint(report.nftables.active, report.nftables.lo_skip, report.nftables.fwmark),
        tone:
          report.nftables.active && report.nftables.lo_skip && report.nftables.fwmark
            ? "ok"
            : "bad",
      },
      {
        label: d.lists,
        value: `${report.lists_and_bins.general_domains ?? "?"} доменов (общий), ${report.lists_and_bins.google_domains ?? "?"} (google), .bin: ${bins.length}, пустых: ${emptyBins}`,
        tone: emptyBins > 0 || report.lists_and_bins.general_domains === null ? "warn" : "ok",
      },
      {
        label: d.conflicts,
        value: d.conflictsHint(conflicts),
        tone: conflicts === 0 ? "ok" : "bad",
      },
      {
        label: d.proxies,
        value: d.proxiesHint(
          tg.installed ? (tg.listening ? `активен на ${tg.port}` : `не слушает ${tg.port}`) : "не установлен",
          socks.set ? (socks.ok ? "отвечает" : socks.error ?? "не отвечает") : "не задан",
        ),
        tone:
          (socks.set && !socks.ok) || (tg.installed && tg.running && !tg.listening)
            ? "bad"
            : "ok",
      },
      {
        label: d.tcpTimestamps,
        value: d.tcpTimestampHint(report.tcp_timestamps),
        tone: report.tcp_timestamps === true ? "ok" : report.tcp_timestamps === false ? "bad" : "warn",
      },
      {
        label: d.modules,
        value: d.modulesHint(
          report.kernel_nfqueue,
          report.deps.missing,
          report.distro,
        ) + (report.deps.install_command ? ` — ${d.installCommand(report.deps.install_command)}` : ""),
        tone: report.kernel_nfqueue && !report.deps.missing.length ? "ok" : "bad",
      },
    ];
    return cells;
  }

  // The report is mirrored out so a remount (wizard, reload) starts from it too.
  $effect(() => {
    last = report;
  });

  // The tab opens on the cached report at once and refreshes in the background: the checks are
  // external commands and network, the switch itself must not wait for them. Every visit to the
  // tab refreshes, `checking` only marks the running update.
  $effect(() => {
    if (app.tab === "diagnostics") void doctor();
  });
</script>

<div class="row spread">
  <h1>{S.tabs.diagnostics}</h1>
  <div class="row">
    {#if checking && report}<span class="muted">{S.diagnostics.checking}</span>{/if}
    <button disabled={checking || app.busy} onclick={() => void doctor()}>
      {checking ? S.diagnostics.checking : S.diagnostics.check}
    </button>
  </div>
</div>

{#if report}
  <!-- Блок 1: Здоровье системы -->
  <section class="card">
    <h2>{S.diagnostics.healthTitle}</h2>
    <div class="checks">
      {#each cells(report) as cell (cell.label)}
        <div class="cell {cell.tone}">
          <span class="dot" aria-hidden="true">{cell.tone === "ok" ? "🟢" : cell.tone === "warn" ? "🟡" : "🔴"}</span>
          <div>
            <strong>{cell.label}</strong>
            <p>{cell.value}</p>
          </div>
        </div>
      {/each}
    </div>

    {#if report.issues.length}
      <div class="issues">
        <h3>{S.diagnostics.issuesTitle}</h3>
        {#each report.issues as issue (issue.text)}
          <div class="issue bad">
            <p>{issue.text}</p>
            {#if issue.fix}
              <button disabled={app.busy}
                onclick={() => issue.fix && void fix(issue.fix)}>{S.diagnostics.fix}</button>
            {/if}
          </div>
        {/each}
        <button class="primary" disabled={app.busy}
          onclick={() => void fixAll()}>{S.diagnostics.fixAll}</button>
      </div>
    {:else}
      <p class="ok">{S.diagnostics.noIssues}</p>
    {/if}
  </section>

  <!-- Блок 2: Probe -->
  <section class="card">
    <h2>{S.diagnostics.probe.label}</h2>
    <form
      class="row"
      onsubmit={(event) => {
        event.preventDefault();
        void probe();
      }}
    >
      <input
        class="grow"
        placeholder={S.diagnostics.probe.hint}
        bind:value={target}
        disabled={probeBusy || app.busy}
      />
      <button type="submit" disabled={probeBusy || app.busy || !target.trim()}>
        {S.diagnostics.probe.check}
      </button>
    </form>
    <div class="chips">
      {#each CHIPS as [label, subject] (label)}
        <button class="badge" disabled={probeBusy || app.busy} onclick={() => void probe(subject)}>
          {label}
        </button>
      {/each}
    </div>

    <!-- Интерактивные сценарии: углублённая диагностика реального трафика -->
    <div class="chips">
      <button class="badge" disabled={serviceBusy !== null || app.busy}
        onclick={() => void diagnoseService("discord")}>
        {serviceBusy === "discord" ? S.diagnostics.serviceDiag.running : S.diagnostics.serviceDiag.discord}
      </button>
      <button class="badge" disabled={serviceBusy !== null || app.busy}
        onclick={() => void diagnoseService("youtube")}>
        {serviceBusy === "youtube" ? S.diagnostics.serviceDiag.running : S.diagnostics.serviceDiag.youtube}
      </button>
      <button class="badge" disabled={serviceBusy !== null || app.busy}
        onclick={() => void diagnoseService("games")}>
        {serviceBusy === "games" ? S.diagnostics.serviceDiag.running : S.diagnostics.serviceDiag.games}
      </button>
    </div>

    {#if serviceReport}
      <div class="service-report">
        <h3>
          {#if serviceReport.service === "discord"}🎧 Discord{:else if serviceReport.service === "youtube"}🎬 YouTube{:else}🎮 Игры{/if}
          <span class="muted">{S.diagnostics.serviceDiag.total(serviceReport.total_ms)}</span>
        </h3>
        <div class="chips">
          {#each serviceReport.components as comp (comp.name)}
            <span class="badge {comp.ok ? 'ok' : 'bad'}">
              {comp.ok ? "🟢" : "🔴"} {comp.name}: {comp.detail}
            </span>
          {/each}
        </div>
        <div class="verdict">
          <strong>{S.diagnostics.serviceDiag.verdict}</strong>
          <p>{serviceReport.verdict}</p>
        </div>
      </div>
    {/if}

    {#if result}
      <div class="probe">
        <div class="probe-part">
          <h3>{S.diagnostics.probe.dns} — {result.host}</h3>
          {#if result.resolved_ips.length}
            <p>{result.resolved_ips.join(", ")}</p>
          {:else}
            <p class="warn">{S.diagnostics.probe.dnsEmpty}</p>
          {/if}
        </div>
        <div class="probe-part">
          <h3>{S.diagnostics.probe.rules}</h3>
          <div class="chips">
            {#if result.matching.in_list_general}
              <span class="badge">{S.diagnostics.probe.inGeneral}</span>
            {/if}
            {#if result.matching.in_list_google}
              <span class="badge">{S.diagnostics.probe.inGoogle}</span>
            {/if}
            {#if result.matching.excluded_domain}
              <span class="badge warn">{S.diagnostics.probe.excludedDomain}</span>
            {/if}
            {#if result.matching.excluded_ip}
              <span class="badge warn">{S.diagnostics.probe.excludedIp}</span>
            {/if}
            {#if result.matching.matched_route_rule}
              <span class="badge">{S.diagnostics.probe.routeRule(result.matching.matched_route_rule)}</span>
            {:else}
              <span class="badge muted">{S.diagnostics.probe.noRoute}</span>
            {/if}
          </div>
        </div>
        <div class="probe-part">
          <h3>{S.diagnostics.probe.checks}</h3>
          <div class="chips">
            <span class="badge {result.checks.http.status === 'Ok' ? 'ok' : 'bad'}">
              {S.diagnostics.probe.http}: {result.checks.http.status === "Ok" ? `OK ${result.checks.http.time_ms ?? "?"} мс` : S.status[result.checks.http.status]}
            </span>
            <span class="badge {result.checks.tls12.status === 'Ok' ? 'ok' : 'bad'}">
              {S.diagnostics.probe.tls12}: {result.checks.tls12.status === "Ok" ? `OK ${result.checks.tls12.time_ms ?? "?"} мс` : S.status[result.checks.tls12.status]}
            </span>
            <span class="badge {result.checks.tls13.status === 'Ok' ? 'ok' : 'bad'}">
              {S.diagnostics.probe.tls13}: {result.checks.tls13.status === "Ok" ? `OK ${result.checks.tls13.time_ms ?? "?"} мс` : S.status[result.checks.tls13.status]}
            </span>
            <span class="badge {result.checks.ping_ms ? 'ok' : 'bad'}">
              {S.diagnostics.probe.ping}: {result.checks.ping_ms ? `${result.checks.ping_ms} мс` : "нет ответа"}
            </span>
            {#if result.intercepted_packets !== null}
              <span class="badge {result.intercepted_packets > 0 ? 'ok' : 'warn'}">
                {S.diagnostics.probe.intercepted(result.intercepted_packets)}
              </span>
            {/if}
          </div>
        </div>
        <p class="hint">{summary(result)}</p>
      </div>
    {/if}
  </section>
{/if}

<style>
  h1 {
    font-size: 18px;
    margin: 0;
  }

  h2 {
    margin: 0 0 8px;
  }

  h3 {
    margin: 0;
    font-size: 14px;
  }

  .row {
    display: flex;
    align-items: center;
    gap: 10px;
  }

  .spread {
    justify-content: space-between;
  }

  .checks {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
    gap: 8px;
  }

  .cell {
    display: flex;
    gap: 8px;
    align-items: flex-start;
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 8px 10px;
  }

  .cell p {
    margin: 2px 0 0;
    font-size: 13px;
    color: var(--muted);
  }

  .cell.ok p {
    color: var(--ok, green);
  }

  .cell.bad p {
    color: var(--bad, red);
  }

  .issues {
    margin-top: 10px;
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .issue {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 8px 10px;
  }

  .issue p {
    margin: 0;
    font-size: 13px;
  }

  .chips {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    margin: 8px 0;
  }

  .probe {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .probe-part h3 {
    margin-bottom: 4px;
  }

  .probe-part {
    margin-top: 6px;
  }

  .service-report {
    margin-top: 10px;
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .service-report h3 {
    display: flex;
    justify-content: space-between;
    gap: 10px;
    font-size: 14px;
  }

  .verdict {
    margin-top: 4px;
    border: 1px solid var(--border);
    border-left: 3px solid var(--ok, green);
    border-radius: 8px;
    padding: 8px 10px;
  }

  .verdict p {
    margin: 4px 0 0;
    font-size: 13px;
  }
</style>
