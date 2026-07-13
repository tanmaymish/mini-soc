---
name: verify
description: Build, run, and drive the mini-SOC demo dashboard to verify frontend changes at the GUI surface.
---

# Verifying mini-SOC frontend changes

The interactive surface is the React dashboard in `frontend/`, built in
**demo mode** (no backend needed — the sim engine in `src/simEngine.js`
generates alerts/mitigations client-side).

## Build + serve

```bash
cd frontend
npm install
VITE_DEMO_MODE=true npm run build   # demo bundle (what GitHub Pages ships)
npx vite preview --port 4173 --strictPort &   # serves dist/ at http://localhost:4173/
```

Lint with `npx eslint src`. One pre-existing warning in `LiveAttackMap.jsx`
(ref cleanup) is known noise.

## Drive it (Playwright)

Playwright browsers are pre-installed; launch with the pinned executable —
do NOT run `playwright install`:

```js
const browser = await chromium.launch({ executablePath: '/opt/pw-browsers/chromium' });
```

The UI is an app shell: a left `<aside>` nav rail (Overview / Alerts /
Incidents / Detections / Automation / Simulation) + a top command bar with
global alert search. Each nav item swaps the `<main>` view (state in
`Dashboard.jsx`, no router). The top-bar search (`#alert-search`) jumps to
the Alerts view and filters it. The SOC Defense HUD renders above the view
switch so it persists while you navigate.

Flows worth driving after a dashboard change:
- Click each sidebar item → the top-bar breadcrumb title changes and the
  matching view renders (Overview KPIs+map, Alerts queue, etc.).
- Click an attack tile (e.g. "SQL Injection") → alert appears in the
  Threat Alert Feed, Open Alerts stat increments.
- Keyboard: `1`–`0` launch attacks, `L` toggles Live Fire (continuous
  randomized attacks every 3–8s), `U` unleash all, `R` reset board,
  `/` focuses the alert search, `D` starts/ends SOC Defense.
- SOC Defense (game): `D` or the button starts it. A sticky HUD shows
  integrity / score / combo / wave and a threat queue with per-threat
  "Contain" buttons and breach countdowns. Containing (block or close)
  scores; letting a threat's timer expire damages integrity; at 0 the
  "SOC BREACHED" modal shows the final score + analyst rank. Manual
  attack keys/buttons are muted during a shift. Reconciler/scoring runs
  on a 250ms tick, so allow a beat after clicking before asserting.
- Expand an alert row ("View Evidence") → Analyst actions bar:
  Acknowledge / Resolve / False positive / Block IP.
- Triage buttons update the Status badge, fire a toast (`.toast-in`),
  and Resolve/False-positive drop the Open Alerts stat.
- "Block <ip>" adds a `manual_containment` row to the SOAR mitigations
  feed and relabels the button "IP blocked".

## Gotchas

- Multiple `<table>`s on the page (API map, mitigations, alerts). The
  alert feed is the **last** table: `page.locator('table').last()`.
- Selector collisions: the toolbar has chips labelled "Acknowledged" /
  "False positive" and the action bar has buttons "Acknowledge" /
  "False positive". Use `getByRole('button', { name, exact: true })`
  and scope action buttons to the feed table.
- Most sim attacks auto-run a `BLOCK_IP` playbook, so their "Block" button
  is already disabled. To test manual block, use the
  `privilege_escalation` alert — its playbook disables the user, not the IP.
- The search input's clear "X" has aria-label "Clear search"; the filter
  reset chip is "Clear" — use exact matching.
