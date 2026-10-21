<script lang="ts">
  import { onMount } from "svelte";
  import { commands, type ProxyStatus, type RunSummary } from "$lib/ipc/bindings";
  import { call } from "$lib/api";
  import { app, change, refreshOverview } from "$lib/app.svelte";
  import { latestPerSuite, ms, runDate } from "$lib/format";
  import { S } from "$lib/strings";

  let proxy = $state<ProxyStatus | null>(null);
  let proxyBusy = $state(false);
  let runs = $state<RunSummary[]>([]);

  // The newest run of each kind: a DPI run does not hide the last standard one.
  const latest = $derived(latestPerSuite(runs));

  const cleanStrategy = (name: string | null) => (name ? name.replace(/^zapret2:/, "") : S.overview.noStrategy);

  $effect(() => {
    void app.overview?.last_run?.id;
    void call(S.failed.runs, commands.listRuns()).then((list) => (runs = list ?? []));
  });

  async function checkProxy(): Promise<void> {
    const addr = app.settings?.socks5;
    if (!addr) return;
    proxyBusy = true;
    proxy = (await call(S.failed.proxy, commands.checkProxy(addr))) ?? null;
    proxyBusy = false;
  }

  onMount(() => {
    void refreshOverview();
    void checkProxy();
  });
</script>

{#if app.overview}
  {@const o = app.overview}
  {@const locked = app.busy || o.testing}
  {@const isRunning = o.service === "Running"}

  <!-- Крупный статус-баннер -->
  <div class="banner {isRunning ? 'active' : 'inactive'}">
    <div class="banner-info">
      <span class="banner-icon">{isRunning ? "🟢" : "🔴"}</span>
      <div>
        <h2 class="banner-title">
          {isRunning ? S.overview.bannerActive(cleanStrategy(o.strategy)) : S.overview.bannerInactive}
        </h2>
        <p class="banner-subtitle">
          {#if isRunning}
            {S.overview.interceptorVal}
          {:else if o.strategy}
            {S.overview.strategy}: {cleanStrategy(o.strategy)}
          {:else}
            {S.overview.notRunning}
          {/if}
        </p>
      </div>
    </div>
    <div class="buttons">
      {#if isRunning}
        <button class="danger" disabled={locked} onclick={() => change(S.failed.removeService, () => commands.removeService())}>
          {S.overview.stopBypass}
        </button>
        <button disabled={locked} onclick={() => (app.tab = "strategies")}>
          {S.overview.changeStrategy}
        </button>
      {:else if o.strategy}
        <button class="primary" disabled={locked} onclick={() => change(S.failed.apply, () => commands.applyStrategy(o.strategy!))}>
          {S.overview.enableBypass}
        </button>
        <button disabled={locked} onclick={() => (app.tab = "tests")}>
          {S.overview.pickStrategy}
        </button>
      {:else if o.last_run?.best}
        <button class="primary" disabled={locked} onclick={() => change(S.failed.apply, () => commands.applyBest())}>
          {S.overview.applyBest}
        </button>
        <button disabled={locked} onclick={() => (app.tab = "tests")}>
          {S.overview.pickStrategy}
        </button>
      {:else}
        <button class="primary" disabled={locked} onclick={() => (app.tab = "tests")}>
          {S.overview.pickStrategy}
        </button>
      {/if}
    </div>
  </div>

  <div class="cards">
    <!-- Единая карточка: Состояние движка -->
    <section class="card">
      <h2>{S.overview.engineState}</h2>
      <div class="engine-grid">
        <div class="engine-row">
          <span class="muted">{S.overview.systemdService}:</span>
          <span class={isRunning ? "ok font-bold" : "bad"}>{S.svc[o.service]}</span>
        </div>
        <div class="engine-row">
          <span class="muted">{S.overview.engineVersion}:</span>
          <span>{o.zapret2.version ? `nfqws2 ${o.zapret2.version}` : S.overview.version(null)}</span>
        </div>
        <div class="engine-row">
          <span class="muted">{S.overview.interceptor}:</span>
          <code>{S.overview.interceptorVal}</code>
        </div>
        <div class="engine-row">
          <span class="muted">{S.overview.strategy}:</span>
          <strong>{cleanStrategy(o.strategy)}</strong>
        </div>
      </div>

      {#if !o.zapret2.dir}
        <p class="warn">{S.overview.zapret2OffHint}</p>
        <div class="buttons">
          <button onclick={() => (app.tab = "settings")}>{S.overview.zapret2Connect}</button>
        </div>
      {:else if o.zapret2.error}
        <pre class="bad">{o.zapret2.error}</pre>
      {/if}

      {#if isRunning && !o.winws_running}
        <p class="warn">{S.overview.winwsMissing}</p>
      {/if}

      <div class="quick-section">
        <p>
          {S.overview.quick}:
          {#if o.quick}
            <span class={o.quick.ok ? "ok" : "bad"}>{o.quick.ok ? S.overview.quickOk : S.overview.quickFailed}</span>
          {:else}
            <span class="muted">{S.overview.quickNever}</span>
          {/if}
        </p>
        {#if o.quick}
          <div class="quick-items">
            {#each o.quick.checks as item (item.name)}
              <span class="muted check-pill">
                {item.name}: <strong class={item.status === "Ok" ? "ok" : "bad"}>{item.status === "Ok" ? ms(item.time_ms) : S.status[item.status]}</strong>
              </span>
            {/each}
          </div>
        {/if}
      </div>

      <div class="buttons">
        {#if o.strategy && isRunning}
          <button disabled={locked} onclick={() => change(S.failed.restart, () => commands.restartZapret())}>
            {S.overview.restart}
          </button>
        {:else}
          <button class="primary" disabled={locked} onclick={() => (app.tab = "strategies")}>
            {S.overview.selectStrategy}
          </button>
        {/if}
        <button disabled={locked || !isRunning} onclick={() => change(S.failed.quick, () => commands.quickCheck())}>
          {S.overview.quick}
        </button>
      </div>
    </section>

    <!-- Прокси -->
    <section class="card">
      <h2>{S.overview.proxy}</h2>
      {#if !app.settings?.socks5}
        <p class="muted">{S.overview.proxyNotSet}</p>
      {:else}
        <p>{app.settings.socks5}</p>
        {#if proxyBusy}
          <p class="muted">{S.common.checking}</p>
        {:else if proxy}
          <p class={proxy.ok ? "ok" : "bad"}>{proxy.ok ? S.overview.proxyOk(ms(proxy.latency_ms)) : S.overview.proxyFailed}</p>
          {#if proxy.error}<pre>{proxy.error}</pre>{/if}
        {/if}
        <div class="buttons"><button disabled={proxyBusy} onclick={checkProxy}>{S.common.check}</button></div>
      {/if}
    </section>

    <!-- Последний тест -->
    <section class="card">
      <h2>{S.overview.lastTest}</h2>
      {#each latest as run (run.id)}
        <h3>{run.suite === "Standard" ? S.tests.standard : S.tests.dpi}</h3>
        {#if run.best && run.best_score}
          {@const score = run.best_score}
          <p>{S.overview.best}: <strong>{cleanStrategy(run.best)}</strong></p>
          <p>
            {run.suite === "Standard"
              ? S.overview.errors(score.total - score.ok, score.total, ms(score.median_ms))
              : S.strategies.dpiScore(score.likely_blocked, score.fail)}
          </p>
        {/if}
        <p class="muted">{runDate(run.id)}</p>
      {:else}
        <p class="muted">{S.overview.noTests}</p>
      {/each}
      <div class="buttons">
        <button
          class="primary"
          disabled={locked || !o.last_run?.best}
          onclick={() => change(S.failed.apply, () => commands.applyBest())}
        >
          {S.overview.applyBest}
        </button>
        <button disabled={o.testing} onclick={() => (app.tab = "tests")}>{S.overview.runTests}</button>
      </div>
    </section>
  </div>
{:else}
  <p class="muted">{S.common.loading}</p>
{/if}

<style>
  .banner {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
    padding: 16px 20px;
    border-radius: 10px;
    border: 1px solid var(--border);
    margin-bottom: 4px;
  }

  .banner.active {
    background: rgba(31, 157, 85, 0.12);
    border-color: rgba(31, 157, 85, 0.35);
  }

  .banner.inactive {
    background: rgba(214, 69, 69, 0.1);
    border-color: rgba(214, 69, 69, 0.25);
  }

  :root[data-theme="dark"] .banner.active {
    background: rgba(63, 191, 114, 0.15);
    border-color: rgba(63, 191, 114, 0.3);
  }

  :root[data-theme="dark"] .banner.inactive {
    background: rgba(239, 107, 107, 0.12);
    border-color: rgba(239, 107, 107, 0.25);
  }

  .banner-info {
    display: flex;
    align-items: center;
    gap: 14px;
  }

  .banner-icon {
    font-size: 26px;
    line-height: 1;
  }

  .banner-title {
    margin: 0;
    font-size: 17px;
    font-weight: 600;
  }

  .banner-subtitle {
    margin: 2px 0 0;
    font-size: 13px;
    color: var(--muted);
  }

  .engine-grid {
    display: flex;
    flex-direction: column;
    gap: 6px;
    margin: 10px 0;
  }

  .engine-row {
    display: flex;
    align-items: baseline;
    gap: 8px;
  }

  .font-bold {
    font-weight: 600;
  }

  .quick-section {
    margin-top: 10px;
    padding-top: 10px;
    border-top: 1px solid var(--border);
  }

  .quick-items {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    margin-top: 4px;
  }

  .check-pill {
    display: inline-block;
    padding: 2px 6px;
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 4px;
    font-size: 12px;
  }
</style>
