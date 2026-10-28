<script lang="ts">
  import { onMount } from "svelte";
  import { commands, type ProxyStatus, type RunSummary, type TgWsStatus } from "$lib/ipc/bindings";
  import CopyButton from "../components/CopyButton.svelte";
  import UpdateChecker from "../components/UpdateChecker.svelte";
  import { call } from "$lib/api";
  import { app, change, refreshOverview } from "$lib/app.svelte";
  import { latestPerSuite, ms, runDate } from "$lib/format";
  import { S } from "$lib/strings";

  let proxy = $state<ProxyStatus | null>(null);
  let proxyBusy = $state(false);
  let runs = $state<RunSummary[]>([]);
  let tgws = $state<TgWsStatus | null>(null);
  let tgwsBusy = $state(false);

  // The newest run of each kind: a DPI run does not hide the last standard one.
  const latest = $derived(latestPerSuite(runs));

  const cleanStrategy = (name: string | null) => (name ? name.replace(/^zapret2:/, "") : S.overview.noStrategy);

  $effect(() => {
    void app.overview?.last_run?.id;
    void call(S.failed.runs, commands.listRuns()).then((list) => (runs = list ?? []));
  });

  $effect(() => {
    void app.revision;
    void call(S.failed.tgWsStatus, commands.tgWsStatus()).then((status) => (tgws = status ?? null));
  });

  async function installTgws(): Promise<void> {
    tgwsBusy = true;
    try {
      tgws = (await change(S.failed.tgWsInstall, () => commands.installTgWs())) ?? tgws;
    } finally {
      tgwsBusy = false;
    }
  }

  async function toggleTgws(): Promise<void> {
    if (!tgws) return;
    tgwsBusy = true;
    try {
      tgws = (await change(S.failed.tgWsEnabled, () => commands.setTgWsEnabled(!tgws?.running))) ?? tgws;
    } finally {
      tgwsBusy = false;
    }
  }

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
      <span class="banner-dot"></span>
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
    <div class="banner-buttons">
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
    <section class="card engine">
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
          <div class="quick-items">
            {#if run.suite === "Standard"}
              <span class="check-pill {score.discord.ok === score.discord.total ? "ok" : "warn"}">
                {S.results.discord}: {score.discord.ok}/{score.discord.total}{" · "}{ms(score.discord.median_ms)}
              </span>
              <span class="check-pill {score.youtube.ok === score.youtube.total ? "ok" : "warn"}">
                {S.results.youtube}: {score.youtube.ok}/{score.youtube.total}{" · "}{ms(score.youtube.median_ms)}
              </span>
              <span class="check-pill {score.ping_ok === score.ping_total ? "ok" : "warn"}">
                {S.results.ping}: {score.ping_ok}/{score.ping_total}{" · "}{ms(score.ping_median_ms)}
              </span>
            {:else}
              <span class="check-pill {score.ok === score.total ? "ok" : "warn"}">
                {S.overview.scoreOk(score.ok, score.total)}
              </span>
            {/if}
          </div>
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

    <!-- TG WS Proxy -->
    <section class="card">
      <div class="card-head">
        <h2>{S.overview.tgProxy}</h2>
        <span class="badge" class:ok={tgws?.running}>
          {#if !tgws?.installed}{S.overview.tgProxyAbsent}
          {:else if tgws.running}{S.overview.tgProxyOn(tgws.port)}
          {:else}{S.overview.tgProxyOff}{/if}
        </span>
      </div>
      <p class="muted">{S.overview.tgProxyDesc}</p>
      <div class="buttons">
        {#if !tgws?.installed}
          <button class="primary" disabled={tgwsBusy} onclick={installTgws}>
            {tgwsBusy ? S.common.loading : S.overview.tgProxyInstall}
          </button>
        {:else}
          <button class="primary" disabled={tgwsBusy} onclick={toggleTgws}>
            {tgws.running ? S.overview.tgProxyDisable : S.overview.tgProxyEnable}
          </button>
          <button disabled={tgwsBusy} onclick={() => change(S.failed.tgWsOpen, () => commands.openTgProxy())}>
            {S.overview.tgProxyConnect}
          </button>
          <CopyButton text={() => tgws?.tg_url ?? ""} />
        {/if}
      </div>
    </section>

    <!-- Прокси SOCKS5 -->
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
    <!-- Обновление приложения -->
    <section class="card">
      <h2>{S.update.title}</h2>
      <UpdateChecker />
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
    margin-bottom: 4px;
  }

  .banner.active {
    background: color-mix(in srgb, var(--ok) 7%, var(--panel));
    border: 1px solid color-mix(in srgb, var(--ok) 22%, var(--border));
  }

  .banner.inactive {
    background: var(--panel);
    border: 1px solid var(--border);
  }

  .banner-info {
    display: flex;
    align-items: center;
    gap: 14px;
  }

  /* Спокойный матовый индикатор вместо кислотного эмо-кружка */
  .banner-dot {
    width: 10px;
    height: 10px;
    flex-shrink: 0;
    border-radius: 50%;
    background: color-mix(in srgb, var(--ok) 55%, var(--panel));
  }

  .banner.inactive .banner-dot {
    background: color-mix(in srgb, var(--bad) 40%, var(--muted));
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

  .banner-buttons {
    display: flex;
    align-items: center;
    gap: 10px;
  }

  .banner-buttons button {
    height: 32px;
    line-height: 1;
  }

  /* Приглушённая стоп-кнопка вместо яркой красной обводки */
  .banner-buttons button.danger {
    border-color: color-mix(in srgb, var(--bad) 45%, var(--border));
    color: color-mix(in srgb, var(--bad) 70%, var(--text));
  }

  .cards {
    grid-template-columns: 1fr;
  }

  @media (min-width: 1000px) {
    .cards {
      grid-template-columns: 1.5fr 1fr;
    }
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
  .card .buttons,
  .card .engine-grid {
    margin: 0;
  }

  .engine-grid {
    display: flex;
    flex-direction: column;
    gap: 14px;
  }

  .card-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
  }

  .badge {
    padding: 2px 8px;
    border: 1px solid var(--border);
    border-radius: 6px;
    font-size: 12px;
    color: var(--muted);
    white-space: nowrap;
  }

  /* Одинаковый вертикальный шаг между строками, разделителем, бейджами и кнопками */
  .engine {
    padding: 18px 20px;
  }

  .engine-row {
    display: flex;
    align-items: baseline;
    gap: 8px;
  }

  .font-bold {
    font-weight: 600;
  }

  .engine .quick-section {
    display: flex;
    flex-direction: column;
    gap: 14px;
    padding-top: 14px;
    border-top: 1px solid var(--border);
  }

  .quick-items {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
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
