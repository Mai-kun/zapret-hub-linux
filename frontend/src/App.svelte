<script lang="ts">
  import { onMount } from "svelte";
  import ConfirmDialog from "./components/ConfirmDialog.svelte";
  import Notices from "./components/Notices.svelte";
  import Overview from "./tabs/Overview.svelte";
  import Routes from "./tabs/Routes.svelte";
  import Settings from "./tabs/Settings.svelte";
  import Strategies from "./tabs/Strategies.svelte";
  import Tests from "./tabs/Tests.svelte";
  import Zapret from "./tabs/Zapret.svelte";
  import Wizard from "./Wizard.svelte";
  import { app, change, refreshOverview, start, type Tab } from "$lib/app.svelte";
  import { commands } from "$lib/ipc/bindings";
  import { S } from "$lib/strings";

  const TABS = [
    { id: "overview", label: S.tabs.overview, view: Overview },
    { id: "strategies", label: S.tabs.strategies, view: Strategies },
    { id: "tests", label: S.tabs.tests, view: Tests },
    { id: "zapret", label: S.tabs.zapret, view: Zapret },
    { id: "routes", label: S.tabs.routes, view: Routes },
    { id: "settings", label: S.tabs.settings, view: Settings },
  ] satisfies { id: Tab; label: string; view: unknown }[];

  const current = $derived(TABS.find((tab) => tab.id === app.tab) ?? TABS[0]!);

  const cleanStrategy = (name: string | null) => (name ? name.replace(/^zapret2:/, "") : S.overview.noStrategy);

  onMount(() => void start());

  // Files dropped into a strategies folder by hand announce nothing: coming back to the window reads everything again.
  function onFocus(): void {
    app.revision++;
    void refreshOverview();
  }

  async function toggleBypass(): Promise<void> {
    if (!app.overview) return;
    if (app.overview.service === "Running") {
      await change(S.failed.removeService, () => commands.removeService());
    } else {
      if (app.overview.strategy) {
        await change(S.failed.apply, () => commands.applyStrategy(app.overview!.strategy!));
      } else if (app.overview.last_run?.best) {
        await change(S.failed.apply, () => commands.applyBest());
      } else {
        app.tab = "strategies";
      }
    }
  }
</script>

<svelte:window onfocus={onFocus} />

{#if app.settings && !app.settings.wizard_done}
  <Wizard />
{:else if app.settings}
  <div class="shell">
    <nav>
      {#each TABS as tab (tab.id)}
        <button class="tab" class:active={tab.id === current.id} onclick={() => (app.tab = tab.id)}>{tab.label}</button>
      {/each}
      <div class="nav-controls">
        {#if app.live}<span class="testing warn">{S.overview.testing}</span>{/if}
        {#if app.overview}
          {@const isRunning = app.overview.service === "Running"}
          {@const locked = app.busy || (app.overview.testing ?? false)}
          <div class="bypass-widget" title={isRunning ? `${S.header.bypassActive}: ${cleanStrategy(app.overview.strategy)}` : S.header.bypassInactive}>
            <span class="status-dot {isRunning ? 'online' : 'offline'}"></span>
            <span class="status-label">{isRunning ? S.header.bypassActive : S.header.bypassInactive}</span>
            <button
              class="quick-toggle {isRunning ? 'danger' : 'primary'}"
              disabled={locked}
              onclick={toggleBypass}
            >
              {isRunning ? S.header.turnOff : S.header.turnOn}
            </button>
          </div>
        {/if}
      </div>
    </nav>
    <main>
      <current.view />
    </main>
  </div>
{:else}
  <!-- The settings have not arrived (IPC broken or slow): the page answers for itself instead of white -->
  <p class="loading">{S.common.loading}</p>
{/if}

<Notices />
<ConfirmDialog />

<style>
  .shell {
    display: flex;
    flex-direction: column;
    height: 100vh;
  }

  nav {
    display: flex;
    align-items: center;
    gap: 4px;
    padding: 8px 16px;
    background: var(--panel);
    border-bottom: 1px solid var(--border);
  }

  .tab {
    border: none;
    background: none;
  }

  .tab.active {
    background: var(--hover);
    font-weight: 600;
  }

  .nav-controls {
    margin-left: auto;
    display: flex;
    align-items: center;
    gap: 12px;
  }

  .bypass-widget {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 3px 10px;
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 20px;
    font-size: 12px;
  }

  .status-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    flex-shrink: 0;
  }

  .status-dot.online {
    background: var(--ok);
    box-shadow: 0 0 6px var(--ok);
  }

  .status-dot.offline {
    background: var(--muted);
  }

  .status-label {
    font-weight: 500;
    color: var(--text);
  }

  .quick-toggle {
    padding: 2px 8px;
    font-size: 11px;
    border-radius: 12px;
    line-height: 1.3;
  }

  .loading {
    margin: 40vh auto 0;
    text-align: center;
    color: var(--muted, inherit);
  }

  .testing {
    font-size: 13px;
  }

  main {
    flex: 1;
    display: flex;
    flex-direction: column;
    gap: 14px;
    padding: 16px;
    overflow: auto;
  }
</style>
