<script lang="ts">
  import { commands, type CacheReport } from "$lib/ipc/bindings";
  import { app, change } from "$lib/app.svelte";
  import { confirmation } from "$lib/confirm.svelte";
  import { S } from "$lib/strings";

  let cache = $state<CacheReport[] | null>(null);

  const locked = $derived(app.busy || (app.overview?.testing ?? false));

  async function clearCache(): Promise<void> {
    const sure = await confirmation.ask({ title: S.zapret.cacheTitle, text: S.zapret.cacheText, yes: S.zapret.cacheClear });
    if (sure) cache = (await change(S.failed.cache, () => commands.clearDiscordCache())) ?? null;
  }

  async function removeService(): Promise<void> {
    const sure = await confirmation.ask({
      title: S.zapret.removeTitle,
      text: `${S.zapret.serviceHint}\n\n${S.zapret.removeText}`,
      yes: S.zapret.remove,
      danger: true,
    });
    if (sure) await change(S.failed.removeService, () => commands.removeService());
  }
</script>

<div class="cards">
  <section class="card">
    <h2>{S.zapret.service}</h2>
    <p class="muted">{S.zapret.serviceHint}</p>
    <div class="buttons"><button class="danger" disabled={locked} onclick={removeService}>{S.zapret.remove}</button></div>
  </section>

  <section class="card">
    <h2>{S.zapret.cache}</h2>
    <div class="buttons"><button disabled={app.busy} onclick={clearCache}>{S.zapret.cacheButton}</button></div>
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
  /* A path in the cache report has no space to wrap at: it breaks anywhere rather than spill out of its card. */
  p {
    overflow-wrap: anywhere;
  }
</style>
