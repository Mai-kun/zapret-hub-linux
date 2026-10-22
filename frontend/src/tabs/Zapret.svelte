<script lang="ts">
  import { onMount } from "svelte";
  import { commands, type CacheReport } from "$lib/ipc/bindings";
  import { LINKS } from "$lib/strings";
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
  let logsEl = $state<HTMLPreElement | null>(null);

  const locked = $derived(app.busy || (app.overview?.testing ?? false));
  const isRunning = $derived(app.overview?.service === "Running");
  const svcStatus = $derived(app.overview ? S.svc[app.overview.service] : S.common.loading);
  // A table with rules prints a non-empty listing; anything else is no active table.
  const nftActive = $derived(rules.trim() !== "");

  // The terminal <pre> is at the bottom: jump to the newest lines after each load.
  $effect(() => {
    if (logs && logsEl) logsEl.scrollTop = logsEl.scrollHeight;
  });

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

  async function startService(): Promise<void> {
    await change(S.failed.startService, () => commands.startService());
    void loadRules();
    void loadLogs();
  }

  async function restartService(): Promise<void> {
    await change(S.failed.restartService, () => commands.restartService());
    void loadRules();
    void loadLogs();
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
      text: S.zapret.removeText,
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
  <div class="tier-top">
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
      </div>
      <p class="muted">{S.zapret.serviceHint}</p>
      <div class="buttons">
        {#if app.overview?.service === "NotInstalled"}
          <button class="primary" disabled={locked} onclick={startService}>{S.zapret.start}</button>
        {:else}
          {#if isRunning}
            <button class="danger" disabled={locked} onclick={stopService}>{S.zapret.stop}</button>
          {/if}
          <button disabled={locked} onclick={restartService}>{S.zapret.restart}</button>
          <button class="danger" disabled={locked} onclick={removeService}>{S.zapret.remove}</button>
        {/if}
      </div>
    </section>

    <!-- Card 2: System utilities -->
    <section class="card">
      <h2>{S.zapret.utilsTitle}</h2>
      <p class="muted">{S.zapret.utilsHint}</p>
      <div class="utilities">
        <div class="utility-group">
          <button disabled={flushingDns || app.busy} onclick={flushDns}>
            {flushingDns ? S.common.loading : S.zapret.dnsButton}
          </button>
          <p class="muted hint">{S.zapret.dnsHint}</p>
        </div>
        <div class="utility-group">
          <button disabled={app.busy} onclick={clearCache}>{S.zapret.cacheButton}</button>
          <p class="muted hint">{S.zapret.cacheHint}</p>
        </div>
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

    <!-- Card 3: TG WS Proxy (in development) -->
    <section class="card">
      <h2>{S.zapret.proxyTitle} <span class="badge muted">{S.zapret.proxyStatus}</span></h2>
      <p class="muted">{S.zapret.proxyDesc}</p>
      <div>
        <button class="link" onclick={() => call(S.failed.open, commands.openUrl(LINKS.tgWsProxy))}>
          {S.zapret.proxyLink}
        </button>
      </div>
    </section>
  </div>

  <!-- Card 4: nftables monitor (full width) -->
  <section class="card">
    <div class="card-header">
      <h2>
        {S.zapret.nftTitle}
        <span class="badge" class:ok={nftActive} class:muted={!nftActive}>
          {nftActive ? S.zapret.nftActive : S.zapret.nftInactive}
        </span>
      </h2>
      <button disabled={loadingRules} onclick={loadRules}>
        {loadingRules ? S.common.loading : S.zapret.nftRefresh}
      </button>
    </div>
    <p class="muted">{S.zapret.nftHint}</p>
    <pre>{rules || (loadingRules ? S.common.loading : S.zapret.nftEmpty)}</pre>
  </section>

  <!-- Card 5: journalctl logs (full width) -->
  <section class="card">
    <div class="card-header">
      <h2>{S.zapret.logsTitle}</h2>
      <div class="header-buttons">
        <button disabled={!logs} onclick={copyLogs}>
          {logsCopied ? S.zapret.logsCopied : S.zapret.logsCopy}
        </button>
        <button disabled={loadingLogs} onclick={loadLogs}>
          {loadingLogs ? S.common.loading : S.zapret.logsRefresh}
        </button>
      </div>
    </div>
    <p class="muted">{S.zapret.logsHint}</p>
    <pre class="logs" bind:this={logsEl}>{logs || (loadingLogs ? S.common.loading : S.zapret.logsEmpty)}</pre>
  </section>
</div>

<style>
  /* Scoped override of app.css: the old auto-fit split the two wide cards in half. */
  .cards {
    display: flex;
    flex-direction: column;
    gap: 14px;
  }

  .tier-top {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    gap: 14px;
  }

  .card {
    display: flex;
    flex-direction: column;
    gap: 14px;
  }

  .card h2,
  .card h3,
  .card p,
  .card pre,
  .card .buttons {
    margin: 0;
  }

  .svc-status {
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .utilities {
    display: flex;
    flex-direction: column;
    gap: 16px;
  }

  .utility-group {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .utility-group p {
    margin: 0;
  }

  .card-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 12px;
  }

  .card-header h2 {
    margin: 0;
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .header-buttons {
    display: flex;
    gap: 8px;
  }

  pre {
    margin: 0;
    height: 240px;
    max-height: 500px;
    overflow-y: auto;
    font-family: "Cascadia Mono", Consolas, "Fira Code", monospace;
    font-size: 12px;
  }

  pre.logs {
    height: 320px;
    background: #0d1117;
    color: #3fb950;
    border-color: #30363d;
    line-height: 1.4;
  }

  p {
    overflow-wrap: anywhere;
  }
</style>
