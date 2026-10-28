<script lang="ts">
  import { onMount } from "svelte";
  import { commands, type ExclusionRule, type FlowRow, type Preset, type RouterState, type RouterStatus, type RoutesView, type Rule } from "$lib/ipc/bindings";
  import { app, change } from "$lib/app.svelte";
  import { call } from "$lib/api";
  import { confirmation } from "$lib/confirm.svelte";
  import { notices } from "$lib/notices.svelte";
  import { bytes, programName, proxyLabel, routeSummary, trafficLabel, viaLabel } from "$lib/format";
  import { plural, S } from "$lib/strings";
  import RouteEditor from "./RouteEditor.svelte";

  let status = $state<RouterStatus | null>(null);
  let view = $state<RoutesView | null>(null);
  let flows = $state<FlowRow[]>([]);
  let all = $state(false);
  let editing = $state<{ rule: Rule; create: boolean } | null>(null);

  // The «Исключения из zapret» groups: named groups from `data/exclusions.toml`, loaded once on
  // open. One group is being edited at a time in the editor below.
  let exclusions = $state<ExclusionRule[] | null>(null);
  let editingExclusion = $state<{
    index: number | null;
    name: string;
    enabled: boolean;
    domains: string;
    ips: string;
    apps: string;
    ports: string;
  } | null>(null);
  let exclusionsSaved = $state(false);

  const blankRule = (): ExclusionRule => ({
    name: "",
    enabled: true,
    domains: [],
    ips: [],
    ports: [],
    apps: [],
  });

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
    void call(S.failed.exclusions, commands.getExclusionRules()).then((read) => {
      if (!read) return;
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

  /** The save itself. */
  async function saveExclusions(next: ExclusionRule[]): Promise<boolean> {
    const answer = await change(S.failed.exclusions, () => commands.saveExclusionRules(next));
    if (answer === undefined) return false;
    exclusions = next;
    exclusionsSaved = true;
    setTimeout(() => (exclusionsSaved = false), 4000);
    return true;
  }

  async function toggleRule(index: number): Promise<void> {
    if (!exclusions) return;
    const next = exclusions.slice();
    next[index]!.enabled = !next[index]!.enabled;
    await saveExclusions(next);
  }

  async function removeRule(index: number): Promise<void> {
    if (!exclusions) return;
    const rule = exclusions[index]!;
    const sure = await confirmation.ask({
      title: `Удалить группу «${rule.name}»?`,
      text: "Группа исключений будет удалена.",
      yes: S.routes.delete,
    });
    if (!sure) return;
    const next = exclusions.slice();
    next.splice(index, 1);
    await saveExclusions(next);
    if (editingExclusion?.index === index) editingExclusion = null;
  }

  /** The editor open for an existing group, or a blank one for a new group. */
  function editExclusion(index: number | null): void {
    if (!exclusions) return;
    const rule = index === null ? blankRule() : exclusions[index]!;
    editingExclusion = {
      index,
      name: rule.name,
      enabled: rule.enabled,
      domains: rule.domains.join("\n"),
      ips: rule.ips.join("\n"),
      apps: (rule.apps ?? []).join("\n"),
      ports: rule.ports.join(", "),
    };
  }

  async function saveEditing(): Promise<void> {
    if (!exclusions || !editingExclusion) return;
    const { index, name, enabled, domains, ips, apps, ports } = editingExclusion;
    const rule: ExclusionRule = {
      name: name.trim(),
      enabled,
      domains: draftLines(domains),
      ips: draftLines(ips),
      ports: draftPorts(ports),
      apps: draftLines(apps),
    };
    const next = exclusions.slice();
    if (index === null) next.push(rule);
    else next[index] = rule;
    if (await saveExclusions(next)) editingExclusion = null;
  }

  /** A short look at a rule: how many entries each target has. */
  const ruleSummary = (rule: ExclusionRule): string => {
    const parts: string[] = [];
    if (rule.domains.length > 0) parts.push(`${rule.domains.length} ${plural(rule.domains.length, ["домен", "домена", "доменов"])}`);
    if (rule.ips.length > 0) parts.push(`${rule.ips.length} ${plural(rule.ips.length, ["подсеть", "подсети", "подсетей"])}`);
    if ((rule.apps ?? []).length > 0) parts.push(`${(rule.apps ?? []).length} ${plural((rule.apps ?? []).length, ["программа", "программы", "программ"])}`);
    if (rule.ports.length > 0) parts.push(`${rule.ports.length} ${plural(rule.ports.length, ["порт", "порта", "портов"])}`);
    return parts.length > 0 ? parts.join(" · ") : "—";
  };
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
          <label for="excl-name">{S.routes.exclusions.name}</label>
          <input id="excl-name" bind:value={editingExclusion.name} />
          <label class="inline"
            ><input type="checkbox" bind:checked={editingExclusion.enabled} />
            {S.routes.exclusions.enabled}</label
          >
        </div>
        <div class="cols">
          <div>
            <div class="field-header">
              <label for="excl-domains">{S.routes.exclusions.targets.domains}</label>
              <span class="muted hint">{S.routes.exclusions.hints.domains}</span>
            </div>
            <textarea
              id="excl-domains"
              rows="4"
              spellcheck="false"
              bind:value={editingExclusion.domains}
            ></textarea>
          </div>
          <div>
            <div class="field-header">
              <label for="excl-ips">{S.routes.exclusions.targets.ips}</label>
              <span class="muted hint">{S.routes.exclusions.hints.ips}</span>
            </div>
            <textarea id="excl-ips" rows="4" spellcheck="false" bind:value={editingExclusion.ips}></textarea>
          </div>
          <div>
            <div class="field-header">
              <label for="excl-apps">{S.routes.exclusions.targets.apps}</label>
              <span class="muted hint">{S.routes.exclusions.hints.apps}</span>
            </div>
            <textarea
              id="excl-apps"
              rows="4"
              spellcheck="false"
              bind:value={editingExclusion.apps}
            ></textarea>
          </div>
          <div>
            <div class="field-header">
              <label for="excl-ports">{S.routes.exclusions.targets.ports}</label>
              <span class="muted hint">{S.routes.exclusions.hints.ports}</span>
            </div>
            <input
              id="excl-ports"
              bind:value={editingExclusion.ports}
              placeholder={S.routes.exclusions.portPlaceholder}
              aria-label={S.routes.exclusions.targets.ports}
            />
          </div>
        </div>
        <div class="buttons">
          <button class="primary" disabled={app.busy} onclick={saveEditing}>{S.routes.exclusions.save}</button>
          <button onclick={() => (editingExclusion = null)}>{S.common.close}</button>
          {#if exclusionsSaved}<span class="ok">{S.routes.exclusions.saved}</span>{/if}
        </div>
      </div>
    {:else}
      {#if exclusions}
        <div class="groups">
          {#each exclusions ?? [] as rule, i}
            <div class="group">
              <div class="row">
                <label class="inline">
                  <input
                    type="checkbox"
                    checked={rule.enabled}
                    disabled={app.busy}
                    onchange={() => void toggleRule(i)}
                  />
                  <strong>{rule.name}</strong>
                </label>
                <span class="badge muted">{ruleSummary(rule)}</span>
                <span class="grow"></span>
                <button disabled={app.busy} onclick={() => editExclusion(i)}>{S.routes.edit}</button>
                <button class="danger" disabled={app.busy} onclick={() => void removeRule(i)}>{S.routes.delete}</button>

              </div>
            </div>
          {/each}
        </div>
        <div class="buttons">
          <button disabled={app.busy} onclick={() => editExclusion(null)}>{S.routes.exclusions.add}</button>
          {#if exclusionsSaved}<span class="ok">{S.routes.exclusions.saved}</span>{/if}
        </div>
      {:else}
        <p class="muted">{S.common.loading}</p>
      {/if}
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
  .excl-editor .cols {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
    gap: 16px;
    margin: 12px 0;
    align-items: start;
  }
  .excl-editor .cols > div {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }
  .excl-editor .cols textarea {
    flex: 1;
  }
  .field-header {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }
  .field-header .hint {
    margin: 0;
  }
</style>
