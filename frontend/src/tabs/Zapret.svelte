<script lang="ts">
  import { onMount } from "svelte";
  import { commands, type CacheReport } from "$lib/ipc/bindings";
  import { app, change } from "$lib/app.svelte";
  import { call } from "$lib/api";
  import { confirmation } from "$lib/confirm.svelte";
  import { notices } from "$lib/notices.svelte";
  import { S } from "$lib/strings";

  let cache = $state<CacheReport[] | null>(null);
  let rules = $state<string>("");
  let loadingRules = $state<boolean>(false);
  let logs = $state<string>("");
  let loadingLogs = $state<boolean>(false);
  let logsCopied = $state<boolean>(false);
  let flushingDns = $state<boolean>(false);

  const locked = $derived(app.busy || (app.overview?.testing ?? false));
  const isRunning = $derived(app.overview?.service === "Running");
  const svcStatus = $derived(app.overview ? S.svc[app.overview.service] : S.common.loading);

  onMount(() => {
    void loadRules();
    void loadLogs();
  });

  async function loadRules(): Promise<void> {
    loadingRules = true;
    try {
      const res = await call(S.failed.nftRules, commands.nftRules());
      if (res !== undefined) rules = res;
    } finally {
      loadingRules = false;
    }
  }

  async function loadLogs(): Promise<void> {
    loadingLogs = true;
    try {
      const res = await call(S.failed.serviceLogs, commands.serviceLogs());
      if (res !== undefined) logs = res;
    } finally {
      loadingLogs = false;
    }
  }

  async function copyLogs(): Promise<void> {
    if (!logs) return;
    try {
      await navigator.clipboard.writeText(logs);
      logsCopied = true;
      setTimeout(() => (logsCopied = false), 1500);
    } catch (err) {
      notices.push({ level: "Error", title: S.common.copyFailed(String(err)), text: "" });
    }
  }

  async function stopService(): Promise<void> {
    const sure = await confirmation.ask({
      title: S.zapret.stopTitle,
      text: S.zapret.stopText,
      yes: S.zapret.stop,
    });
    if (sure) {
      await change(S.failed.stopService, () => commands.stopService());
      void loadRules();
      void loadLogs();
    }
  }

  async function removeService(): Promise<void> {
    const sure = await confirmation.ask({
      title: S.zapret.removeTitle,
      text: `${S.zapret.serviceHint}\n\n${S.zapret.removeText}`,
      yes: S.zapret.remove,
      danger: true,
    });
    if (sure) {
      await change(S.failed.removeService, () => commands.removeService());
      void loadRules();
      void loadLogs();
    }
  }

  async function flushDns(): Promise<void> {
    flushingDns = true;
    try {
      const res = await change(S.failed.flushDns, () => commands.flushDns());
      if (res !== undefined) {
        notices.push({ level: "Info", title: S.zapret.dnsFlushed, text: "" });
      }
    } finally {
      flushingDns = false;
    }
  }

  async function clearCache(): Promise<void> {
    const sure = await confirmation.ask({
      title: S.zapret.cacheTitle,
      text: S.zapret.cacheText,
      yes: S.zapret.cacheClear,
    });
    if (sure) {
      cache = (await change(S.failed.cache, () => commands.clearDiscordCache())) ?? null;
    }
  }
</script>

<div class="cards">
  <!-- Card 1: Service management -->
  <section class="card">
    <h2>{S.zapret.service}</h2>
    <div class="svc-status">
      <span>{S.zapret.statusLabel}:</span>
      <span
        class="badge"
        class:ok={isRunning}
        class:warn={app.overview?.service === "Stopped"}
        class:muted={app.overview?.service === "NotInstalled"}
      >
        {svcStatus}
      </span>
      {#if app.overview?.service_name}
        <span class="muted">({app.overview.service_name})</span>
      {/if}
    </div>
    <p class="muted">{S.zapret.serviceHint}</p>
    <div class="buttons">
      <button class="danger" disabled={locked || !isRunning} onclick={stopService}>
        {S.zapret.stop}
      </button>
      <button class="danger" disabled={locked || app.overview?.service === "NotInstalled"} onclick={removeService}>
        {S.zapret.remove}
      </button>
    </div>
  </section>

  <!-- Card 2: nftables monitor -->
  <section class="card">
    <div class="card-header">
      <h2>{S.zapret.nftTitle}</h2>
      <button disabled={loadingRules} onclick={loadRules}>
        {loadingRules ? S.common.loading : S.zapret.nftRefresh}
      </button>
    </div>
    <p class="muted">{S.zapret.nftHint}</p>
    <pre>{rules || (loadingRules ? S.common.loading : S.zapret.nftEmpty)}</pre>
  </section>

  <!-- Card 3: journalctl logs -->
  <section class="card">
    <div class="card-header">
      <h2>{S.zapret.logsTitle}</h2>
      <div class="buttons">
        <button disabled={!logs} onclick={copyLogs}>
          {logsCopied ? S.zapret.logsCopied : S.zapret.logsCopy}
        </button>
        <button disabled={loadingLogs} onclick={loadLogs}>
          {loadingLogs ? S.common.loading : S.zapret.logsRefresh}
        </button>
      </div>
    </div>
    <p class="muted">{S.zapret.logsHint}</p>
    <pre class="logs">{logs || (loadingLogs ? S.common.loading : S.zapret.logsEmpty)}</pre>
  </section>

  <!-- Card 4: System utilities -->
  <section class="card">
    <h2>{S.zapret.utilsTitle}</h2>
    <p class="muted">{S.zapret.utilsHint}</p>
    <div class="buttons">
      <button disabled={flushingDns || app.busy} onclick={flushDns}>
        {flushingDns ? S.common.loading : S.zapret.dnsButton}
      </button>
      <button disabled={app.busy} onclick={clearCache}>
        {S.zapret.cacheButton}
      </button>
    </div>
    {#if cache}
      {#if cache.length === 0}<p class="muted">{S.zapret.cacheNone}</p>{/if}
      {#each cache as report (report.install)}
        <h3>{report.install} {#if report.closed}<span class="muted">{S.zapret.cacheClosed}</span>{/if}</h3>
        {#each report.dirs as dir (dir.path)}
          <p class={dir.outcome === "Failed" ? "bad" : "muted"}>
            {dir.path} — {S.zapret.cacheOutcome[dir.outcome]}{dir.error ? `: ${dir.error}` : ""}
          </p>
        {/each}
      {/each}
    {/if}
  </section>
</div>

<style>
  .svc-status {
    display: flex;
    align-items: center;
    gap: 8px;
    margin: 8px 0 4px;
  }

  .card-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 12px;
  }

  .card-header h2 {
    margin: 0;
  }

  pre {
    margin: 8px 0 0;
    max-height: 250px;
    overflow-y: auto;
    font-family: "Cascadia Mono", Consolas, "Fira Code", monospace;
    font-size: 12px;
  }

  pre.logs {
    background: #0d1117;
    color: #3fb950;
    border-color: #30363d;
    max-height: 320px;
    font-size: 11px;
    line-height: 1.4;
  }

  p {
    overflow-wrap: anywhere;
  }
</style>
