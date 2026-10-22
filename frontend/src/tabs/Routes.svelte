<script lang="ts">
  import { onMount } from "svelte";
  import { commands, type Exclusions, type FlowRow, type Preset, type RouterState, type RouterStatus, type RoutesView, type Rule } from "$lib/ipc/bindings";
  import { app, change } from "$lib/app.svelte";
  import { call } from "$lib/api";
  import { confirmation } from "$lib/confirm.svelte";
  import { notices } from "$lib/notices.svelte";
  import { bytes, programName, proxyLabel, routeSummary, trafficLabel, viaLabel } from "$lib/format";
  import { S } from "$lib/strings";
  import RouteEditor from "./RouteEditor.svelte";

  let status = $state<RouterStatus | null>(null);
  let view = $state<RoutesView | null>(null);
  let flows = $state<FlowRow[]>([]);
  let all = $state(false);
  let editing = $state<{ rule: Rule; create: boolean } | null>(null);

  // The «Исключения из zapret» groups: content on load + which group is switched off. A switched
  // off group is stored as `#! entry` lines (the app reads those back), so nothing is lost.
  type ExclKind = "domains" | "ips" | "ports";
  const OFF_KEY = "zapret-hub-exclusions-off";
  let exclusions = $state<Exclusions | null>(null);
  let off = $state<Record<ExclKind, boolean>>({ domains: false, ips: false, ports: false });
  let editingExclusion = $state<{ target: ExclKind; draft: string } | null>(null);
  let exclusionsSaved = $state(false);

  const on = $derived(status !== null && status.state.state !== "Off");
  const error = $derived(view?.error ?? status?.rules_error ?? null);
  const dohBlind = $derived(!!view?.system_doh && view.rules.some((r) => r.rule.enabled && r.rule.domains.length > 0));

  // Every read counts: an answer older than the latest asked (say, before «все» flipped) is dropped.
  let asked = 0;
  // One notice for a run of failed reads, not one a second.
  let failing = false;

  // Latency and flows announce nothing: read once a second while the tab is open and the window is shown.
  async function refresh(): Promise<void> {
    if (document.hidden) return;
    const mine = ++asked;
    try {
      const answer = await Promise.all([commands.routerStatus(), commands.listRoutes(), commands.routeFlows(all)]);
      failing = false;
      if (mine === asked) [status, view, flows] = answer;
    } catch (err) {
      if (!failing) notices.push({ level: "Error", title: S.failed.routes, text: String(err) });
      failing = true;
    }
  }

  onMount(() => {
    void call(S.failed.routes, commands.getExclusions()).then((read) => {
      if (!read) return;
      // A switch off of an earlier session comes back from the local store: the file only knows
      // the (still kept) `#!` entries.
      const remembered = localStorage.getItem(OFF_KEY);
      if (remembered) off = { ...off, ...JSON.parse(remembered) };
      exclusions = read;
    });

    let timer: ReturnType<typeof setTimeout> | undefined;
    let alive = true;
    // The next read starts a second after the last answered: a slow `listRoutes` does not pile them up.
    const tick = async (): Promise<void> => {
      try {
        await refresh();
      } finally {
        if (alive) timer = setTimeout(tick, 1000);
      }
    };
    void tick();
    return () => {
      alive = false;
      clearTimeout(timer);
    };
  });

  function stateLabel(state: RouterState): { text: string; class: string } {
    switch (state.state) {
      case "Off":
        return { text: S.routes.off, class: "muted" };
      case "Running":
        return { text: S.routes.on, class: "ok" };
      case "Paused":
        return { text: S.routes.paused, class: "warn" };
      case "Unavailable":
        return { text: S.routes.unavailable(state.reason), class: "bad" };
    }
  }

  const clock = (seconds: number): string => `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, "0")}`;

  // A box shows what the router says, not the click: it moves once the answer or the next read does.
  async function toggle(event: Event & { currentTarget: HTMLInputElement }): Promise<void> {
    event.currentTarget.checked = on;
    const answer = await change(S.failed.router, () => commands.setRouterEnabled(!on));
    if (answer) status = answer;
  }

  async function setEnabled(event: Event & { currentTarget: HTMLInputElement }, name: string, enabled: boolean): Promise<void> {
    event.currentTarget.checked = !enabled;
    await change(S.failed.route, () => commands.setRouteEnabled(name, enabled));
    void refresh();
  }

  function showAll(value: boolean): void {
    all = value;
    void refresh();
  }

  async function addPreset(preset: Preset): Promise<void> {
    await change(S.failed.preset, () => commands.addRoutePreset(preset));
    void refresh();
  }

  async function remove(name: string): Promise<void> {
    const sure = await confirmation.ask({ title: S.routes.deleteTitle(name), text: S.routes.deleteText, yes: S.routes.delete, danger: true });
    if (!sure) return;
    await change(S.failed.deleteRoute, () => commands.deleteRoute(name));
    void refresh();
  }

  function clearFlows(): void {
    // The closed rows live here alone: the next read brings the open flows back as they are.
    flows = flows.filter((flow) => !flow.closed);
  }

  // ————— the exclusions card —————

  /** One entry per line, blanks gone. */
  const draftLines = (text: string): string[] =>
    text
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean);

  const draftPorts = (text: string): string[] => text.split(/[\s,]+/).filter(Boolean);

  /** A short look at the group: the first five entries, then «…». */
  const preview = (list: string[] | undefined): string =>
    list === undefined || list.length === 0 ? "—" : list.slice(0, 5).join(", ") + (list.length > 5 ? "…" : "");

  /** The save itself, with the switched off groups marked `#!` (ports go out as an empty list). */
  async function saveExclusions(next: Exclusions): Promise<boolean> {
    const marked = (entries: string[], disabled: boolean): string[] =>
      disabled ? entries.map((entry) => `#! ${entry}`) : entries;
    const answer = await change(S.failed.exclusions, () =>
      commands.saveExclusions({
        domains: marked(next.domains, off.domains),
        ips: marked(next.ips, off.ips),
        ports: off.ports ? [] : next.ports,
      }),
    );
    if (answer === undefined) return false;
    exclusions = next;
    exclusionsSaved = true;
    setTimeout(() => (exclusionsSaved = false), 4000);
    return true;
  }

  async function toggleExclusion(kind: ExclKind): Promise<void> {
    off = { ...off, [kind]: !off[kind] };
    localStorage.setItem(OFF_KEY, JSON.stringify(off));
    if (exclusions) void saveExclusions({ ...exclusions });
  }

  /** The editor open for an existing group: its entries as they are kept. */
  function editExclusion(kind: ExclKind): void {
    if (!exclusions) return;
    editingExclusion = {
      target: kind,
      draft: kind === "ports" ? exclusions.ports.join(", ") : exclusions[kind].join("\n"),
    };
  }

  async function saveEditing(): Promise<void> {
    if (!exclusions || !editingExclusion) return;
    const { target, draft } = editingExclusion;
    const entryLists: Exclusions = {
      ...exclusions,
      [target]: target === "ports" ? draftPorts(draft) : draftLines(draft),
    };
    if (await saveExclusions(entryLists)) editingExclusion = null;
  }
</script>

{#if status}
  {@const state = stateLabel(status.state)}
  <section class="card">
    <div class="row">
      <label class="inline">
        <input type="checkbox" checked={on} disabled={app.busy} onchange={toggle} />
        <strong>{S.routes.title}</strong>
      </label>
      <span class={state.class}>{state.text}</span>
    </div>
    <p>{S.routes.about}</p>
    {#if app.settings?.socks5}
      <p>
        {S.routes.socks5(app.settings.socks5)}
        <span class={status.proxy.state === "Ok" ? "ok" : status.proxy.state === "Unknown" ? "muted" : "bad"}>{proxyLabel(status.proxy)}</span>
      </p>
    {:else}
      <p class="warn">
        {S.routes.proxyMissing}
        <button class="link" onclick={() => (app.tab = "settings")}>{S.routes.proxyGo}</button>
      </p>
    {/if}
    <p class="counters">{S.routes.proxied(trafficLabel(status.totals.proxied))} · {S.routes.direct(trafficLabel(status.totals.direct))}</p>
    {#if error}<pre class="bad">{error}</pre>{/if}
    {#if dohBlind}<p class="warn">{S.routes.systemDoh}</p>{/if}

    <hr class="section-divider" />

    <div class="rules">
      {#if editing}
        <RouteEditor
          rule={editing.rule}
          create={editing.create}
          onClose={() => {
            editing = null;
            void refresh();
          }}
        />
      {:else}
        <h2>{S.routes.rules}</h2>
        {#if view && view.rules.length > 0}
          <table>
            <tbody>
              {#each view.rules as row (row.rule.name)}
                <tr>
                  <td>
                    <input
                      type="checkbox"
                      aria-label={S.routes.enabled}
                      checked={row.rule.enabled}
                      disabled={app.busy}
                      onchange={(event) => setEnabled(event, row.rule.name, !row.rule.enabled)}
                    />
                  </td>
                  <td><strong>{row.rule.name}</strong></td>
                  <td class="muted">{routeSummary(row.rule)}</td>
                  <td class="muted">{trafficLabel(row.traffic)}</td>
                  <td class="actions">
                    <button onclick={() => (editing = { rule: $state.snapshot(row.rule), create: false })}>{S.routes.edit}</button>
                    <button class="danger" disabled={app.busy} onclick={() => remove(row.rule.name)}>{S.routes.delete}</button>
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        {:else}
          <p class="muted">{S.routes.noRules}</p>
        {/if}
        <div class="buttons">
          <button
            onclick={() => (editing = { rule: { name: "", enabled: true, protocol: "udp", ports: [], ips: [], domains: [], apps: [] }, create: true })}
          >
            {S.routes.newRule}
          </button>
        </div>
        <div class="row chips">
          <span class="muted">{S.routes.chips}</span>
          {#each Object.entries(S.routes.presets) as [preset, label] (preset)}
            <button disabled={app.busy} onclick={() => addPreset(preset as Preset)}>{label}</button>
          {/each}
        </div>
      {/if}
    </div>
  </section>

  <section class="card">
    <h2>{S.routes.exclusions.title}</h2>
    <p>{S.routes.exclusions.about}</p>

    {#if editingExclusion}
      <div class="excl-editor">
        <div class="row">
          <strong>{editingExclusion.target === "domains" ? S.routes.exclusions.groups.domainsRu : editingExclusion.target === "ips" ? S.routes.exclusions.groups.local : S.routes.exclusions.groups.p2p}</strong>
        </div>
        <p class="muted">{S.routes.exclusions.hints[editingExclusion.target]}</p>
        {#if editingExclusion.target === "ports"}
          <input
            bind:value={editingExclusion.draft}
            placeholder={S.routes.exclusions.portPlaceholder}
            aria-label={S.routes.exclusions.targets.ports}
          />
        {:else}
          <textarea
            rows="5"
            spellcheck="false"
            bind:value={editingExclusion.draft}
            aria-label={S.routes.exclusions.targets[editingExclusion.target]}
          ></textarea>
        {/if}
        <div class="buttons">
          <button class="primary" disabled={app.busy} onclick={saveEditing}>{S.routes.exclusions.save}</button>
          <button onclick={() => (editingExclusion = null)}>{S.common.close}</button>
          {#if exclusionsSaved}<span class="ok">{S.routes.exclusions.saved}</span>{/if}
        </div>
      </div>
    {:else}
      <div class="groups">
        <div class="group" class:muted={off.domains}>
          <div class="row">
            <label class="inline">
              <input type="checkbox" checked={!off.domains} disabled={!exclusions || app.busy} onchange={() => toggleExclusion("domains")} />
              <strong>{S.routes.exclusions.groups.domainsRu}</strong>
            </label>
            <span class="badge">{exclusions ? S.routes.exclusions.counts.domains(exclusions.domains.length) : "…"}</span>
            <span class="grow"></span>
            <button disabled={!exclusions || app.busy} onclick={() => editExclusion("domains")}>{S.routes.edit}</button>
          </div>
          <p class="muted">{preview(exclusions?.domains)}</p>
        </div>
        <div class="group" class:muted={off.ips}>
          <div class="row">
            <label class="inline">
              <input type="checkbox" checked={!off.ips} disabled={!exclusions || app.busy} onchange={() => toggleExclusion("ips")} />
              <strong>{S.routes.exclusions.groups.local}</strong>
            </label>
            <span class="badge">{exclusions ? S.routes.exclusions.counts.subnets(exclusions.ips.length) : "…"}</span>
            <span class="grow"></span>
            <button disabled={!exclusions || app.busy} onclick={() => editExclusion("ips")}>{S.routes.edit}</button>
          </div>
          <p class="muted">{preview(exclusions?.ips)}</p>
        </div>
        <div class="group" class:muted={off.ports}>
          <div class="row">
            <label class="inline">
              <input type="checkbox" checked={!off.ports} disabled={!exclusions || app.busy} onchange={() => toggleExclusion("ports")} />
              <strong>{S.routes.exclusions.groups.p2p}</strong>
            </label>
            <span class="badge">{exclusions ? (exclusions.ports.length === 0 ? S.routes.exclusions.noPorts : exclusions.ports.join(", ")) : "…"}</span>
            <span class="grow"></span>
            <button disabled={!exclusions || app.busy} onclick={() => editExclusion("ports")}>{S.routes.edit}</button>
          </div>
        </div>
        <div class="group">
          <div class="row">
            <strong>{S.routes.exclusions.groups.bypass}</strong>
          </div>
          <p class="muted">{S.routes.exclusions.bypassHint}</p>
        </div>
        <div class="buttons">
          <button disabled={exclusions === null || app.busy} onclick={() => (editingExclusion = { target: "domains", draft: "" })}>
            {S.routes.exclusions.add}
          </button>
          {#if exclusionsSaved}<span class="ok">{S.routes.exclusions.saved}</span>{/if}
        </div>
      </div>
    {/if}
  </section>

  <section class="card">
    <div class="row">
      <h2 class="grow">{S.routes.flows}</h2>
      <button disabled={!flows.some((flow) => flow.closed)} onclick={clearFlows}>{S.routes.clearFlows}</button>
      <label class="inline"><input type="radio" name="flows" checked={!all} onchange={() => showAll(false)} /> {S.routes.onlyRules}</label>
      <label class="inline"><input type="radio" name="flows" checked={all} onchange={() => showAll(true)} /> {S.routes.all}</label>
    </div>
    <p class="muted">{S.routes.flowsAbout}</p>
    {#if flows.length > 0}
      <table>
        <thead>
          <tr>
            <th>{S.routes.columns.protocol}</th>
            <th>{S.routes.columns.destination}</th>
            <th>{S.routes.columns.domain}</th>
            <th>{S.routes.columns.program}</th>
            <th>{S.routes.columns.rule}</th>
            <th>{S.routes.columns.via}</th>
            <th>{S.routes.columns.up}</th>
            <th>{S.routes.columns.down}</th>
            <th>{S.routes.columns.time}</th>
          </tr>
        </thead>
        <tbody>
          <!-- A flow has no id of its own: rows go by position. -->
          {#each flows as flow, i (i)}
            <tr class:muted={flow.closed}>
              <td>{flow.protocol}</td>
              <td>{flow.destination}</td>
              <td>{flow.domain ?? "—"}</td>
              <td title={flow.program ?? undefined}>{programName(flow.program)}</td>
              <td>{flow.rule ?? "—"}</td>
              <td><span class="badge" class:ok={flow.via.via === "Proxy" || flow.via.via === "Opening"} class:muted={flow.via.via !== "Proxy" && flow.via.via !== "Opening"}>{viaLabel(flow.via)}</span></td>
              <td>{bytes(flow.up ?? 0)}</td>
              <td>{bytes(flow.down ?? 0)}</td>
              <td>{clock(flow.seconds)}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    {:else}
      <p class="muted">{S.routes.noFlows}</p>
    {/if}
  </section>
{:else}
  <p class="muted">{S.common.loading}</p>
{/if}

<style>
  /* Universal spacing: every card's content breathes the same 16px rhythm. */
  section.card {
    display: flex;
    flex-direction: column;
    gap: 16px;
  }
  /* The rhythm lives in the gaps: paragraphs add no margins of their own. */
  section.card p {
    margin: 0;
  }
  hr.section-divider {
    margin: 16px 0;
    border: none;
    border-top: 1px solid var(--border);
  }
  .rules p {
    margin: 0;
  }
  .actions {
    text-align: right;
    white-space: nowrap;
  }
  .chips {
    flex-wrap: wrap;
    margin-top: 10px;
  }
  .groups {
    display: flex;
    flex-direction: column;
    gap: 16px;
  }
  .group {
    display: flex;
    flex-direction: column;
    gap: 4px;
    padding: 8px 12px;
    border: 1px solid var(--border);
    border-radius: 8px;
  }
  .group .badge {
    margin-left: 0;
  }
  .excl-editor {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  .excl-editor .buttons {
    margin-top: 14px;
  }
  .ok {
    margin-left: 10px;
  }
</style>
