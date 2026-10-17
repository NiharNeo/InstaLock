---
name: Cryptographic Assurance Console
colors:
  surface: '#eafdff'
  surface-dim: '#b7e2e6'
  surface-bright: '#eafdff'
  surface-container-lowest: '#ffffff'
  surface-container-low: '#d4fbff'
  surface-container: '#cbf6fa'
  surface-container-high: '#c5f0f4'
  surface-container-highest: '#c0eaef'
  on-surface: '#002022'
  on-surface-variant: '#3e494a'
  inverse-surface: '#08363a'
  inverse-on-surface: '#cef8fd'
  outline: '#6f797a'
  outline-variant: '#bec8ca'
  surface-tint: '#006972'
  primary: '#00535b'
  on-primary: '#ffffff'
  primary-container: '#006d77'
  on-primary-container: '#9becf7'
  inverse-primary: '#82d3de'
  secondary: '#176c46'
  on-secondary: '#ffffff'
  secondary-container: '#a4f4c3'
  on-secondary-container: '#20724b'
  tertiary: '#6e3f00'
  on-tertiary: '#ffffff'
  tertiary-container: '#8f5400'
  on-tertiary-container: '#ffd7b2'
  error: '#ba1a1a'
  on-error: '#ffffff'
  error-container: '#ffdad6'
  on-error-container: '#93000a'
  primary-fixed: '#9ff0fb'
  primary-fixed-dim: '#82d3de'
  on-primary-fixed: '#001f23'
  on-primary-fixed-variant: '#004f56'
  secondary-fixed: '#a4f4c3'
  secondary-fixed-dim: '#88d7a9'
  on-secondary-fixed: '#002111'
  on-secondary-fixed-variant: '#005232'
  tertiary-fixed: '#ffdcbd'
  tertiary-fixed-dim: '#ffb86e'
  on-tertiary-fixed: '#2c1600'
  on-tertiary-fixed-variant: '#693c00'
  background: '#eafdff'
  on-background: '#002022'
  surface-variant: '#c0eaef'
typography:
  headline-xl:
    fontFamily: Source Serif 4
    fontSize: 40px
    fontWeight: '600'
    lineHeight: 48px
    letterSpacing: -0.02em
  headline-xl-mobile:
    fontFamily: Source Serif 4
    fontSize: 30px
    fontWeight: '600'
    lineHeight: 36px
    letterSpacing: -0.01em
  headline-lg:
    fontFamily: Source Serif 4
    fontSize: 28px
    fontWeight: '600'
    lineHeight: 36px
    letterSpacing: -0.015em
  headline-lg-mobile:
    fontFamily: Source Serif 4
    fontSize: 24px
    fontWeight: '600'
    lineHeight: 30px
  headline-md:
    fontFamily: Source Serif 4
    fontSize: 22px
    fontWeight: '600'
    lineHeight: 28px
  title-lg:
    fontFamily: Inter
    fontSize: 18px
    fontWeight: '600'
    lineHeight: 24px
  title-md:
    fontFamily: Inter
    fontSize: 16px
    fontWeight: '600'
    lineHeight: 22px
  body-lg:
    fontFamily: Inter
    fontSize: 16px
    fontWeight: '400'
    lineHeight: 24px
  body-md:
    fontFamily: Inter
    fontSize: 14px
    fontWeight: '400'
    lineHeight: 20px
  body-sm:
    fontFamily: Inter
    fontSize: 12px
    fontWeight: '400'
    lineHeight: 16px
  label-lg:
    fontFamily: JetBrains Mono
    fontSize: 14px
    fontWeight: '500'
    lineHeight: 18px
    letterSpacing: -0.01em
  label-md:
    fontFamily: JetBrains Mono
    fontSize: 12px
    fontWeight: '500'
    lineHeight: 16px
    letterSpacing: 0.02em
  label-sm:
    fontFamily: JetBrains Mono
    fontSize: 11px
    fontWeight: '400'
    lineHeight: 14px
    letterSpacing: 0.04em
  code-body:
    fontFamily: JetBrains Mono
    fontSize: 13px
    fontWeight: '400'
    lineHeight: 20px
rounded:
  sm: 0.125rem
  DEFAULT: 0.25rem
  md: 0.375rem
  lg: 0.5rem
  xl: 0.75rem
  full: 9999px
spacing:
  gutter: 1rem
  gutter-lg: 1.5rem
  margin: 1rem
  margin-md: 1.5rem
  margin-lg: 2.5rem
  space-xs: 0.25rem
  space-sm: 0.5rem
  space-md: 1rem
  space-lg: 1.5rem
  space-xl: 2rem
---

## Brand & Style

This design system serves high-assurance operator consoles, critical infrastructure human-in-the-loop (HITL) authorization checkpoints, and algorithmic safety control rooms. The interface exists for decisive, high-stakes arbitration: approving or denying autonomous AI executions against irreversible real-world resources (monetary transfers, infrastructure updates, sensitive data extraction).

The aesthetic marries institutional editorial authority with precision-grade systems engineering. It avoids frivolous ornamentation, neon synthetic glows, and hyper-casual consumer conventions in favor of a grounded, archival, "defense-in-depth" instrument panel. 

Key attributes:
- **Authoritative & Archival:** Anchored by editorial serif display typography that evokes legal briefs, constitutionality, and irreversible ledgers.
- **Auditable & Exacting:** Tabular clarity, explicit cryptographic provenance, fixed-width parameter alignment, and uncompromising spatial order.
- **Fail-Safe Psychological Tone:** High deliberate friction where errors are catastrophic; immediate optical clarity where status must be appraised in sub-second triage.

## Colors

The system uses a warm, parchment-tinted base to reduce ocular fatigue during prolonged verification shifts, paired with deep cyan-teal and mineral-derived semantic indicators.

### Surface Tiers & Neutral Scales
- **Canvas Base (Light):** `#F7F4EC` (Warm Cream).
- **Surface Layer 1 (Cards, Tables):** `#FFFFFF`.
- **Surface Layer 2 (Inset Wells, Previews):** `#F0EDE4`.
- **Canvas Base (Dark):** `#0B191B` (Deep Dark Slate).
- **Surface Layer 1 (Dark):** `#112326`.
- **Surface Layer 2 (Dark Inset):** `#081314`.
- **Borders & Dividers:** `#C9DCDC` in light mode; `#1F383B` in dark mode.
- **Typography - Ink Primary:** `#0F3B3F` (Deep Petrel Ink).
- **Typography - Ink Secondary:** `#48696B` (Muted Slate Ink).
- **Typography - Subtext / Meta:** `#628082` (De-emphasized Teal Ash).

### Cryptographic & Governance States
- **Allow / Verified / Sign-off:** `#1B6E48` (Forest Emerald). Surface tint: `#E8F4EE`.
- **Deny / Violation / Untrusted:** `#A33B3B` (Crimson Carmine). Surface tint: `#FBEAEA`.
- **Pending / Quorum Required / Stale:** `#C47A1E` (Ochre Amber). Surface tint: `#FEF6EB`.
- **Fail-Closed / Circuit Trip:** `#6E1A24` (Deep Maroon/Cherry). Surface tint: `#F7E6E8`.
- **Adapter / Cryptographic Source:** `#2A5C74` (Cyan Blue-Grey). Surface tint: `#EBF2F7`.

All status indicators require a minimum 4.5:1 contrast ratio against their respective surface treatments to maintain strict WCAG AA compliance. Never convey governance status through hue alone; always pair with explicit iconography or label text.

## Typography

Typography establishes an intentional operational dichotomy:

1. **Constitutional Layer (`Source Serif 4`):** Used exclusively for structural page headers, audit log document names, and gateway policy declarations. This deliberate serif usage emphasizes human judgment and formal authorization.
2. **Operational Layer (`Inter`):** Clear, modern sans-serif for UI orchestration, microcopy, form controls, action button labels, and instructional prompts.
3. **Forensic Layer (`JetBrains Mono`):** Fixed-width clarity for machine attributes: SHA-256 digests, payload diffs, signature fingerprints, public keys, latency meters, and timestamps. Numeric figures within data grids must default to tabular lining (`font-feature-settings: "tnum"`).

## Layout & Spacing

The console employs a high-density, rigid fluid-grid system designed to surface dense relational data with zero layout shift during real-time streaming actions.

### Canvas Grid Model
- **Desktop (≥1280px):** 12-column grid with `gutter-lg` (1.5rem) and `margin-lg` (2.5rem). Optimized for persistent dual-pane views: execution telemetry on the left, action authorization review drawers on the right.
- **Tablet (768px - 1279px):** 8-column layout with `gutter` (1rem) and `margin-md` (1.5rem). Diff inspections transition into layered stacked cards or dedicated modals.
- **Mobile (<768px):** 4-column layout with `gutter` (1rem) and `margin` (1rem). Action triggers lock to the bottom safe-area anchor.

### Density and Flow
Spacing follows a strict 4px base increment. Padding inside data tables, terminal drawers, and cryptographic parameter manifests must remain disciplined (`space-xs` and `space-sm`) to maximize visible vertical diffs without forced scroll states. Outer panel framing uses `space-lg` to create a deliberate perimeter between operational controls.

## Elevation & Depth

This system avoids expressive blur-heavy dropshadows, float illusions, and skeuomorphic lighting. Visual hierarchy is established via **architectonic pane borders, structural contrast, and strict surface containment**.

### Depth Layers
- **Tier 0 (Base Canvas):** Flat, un-elevated background (`#F7F4EC` / `#0B191B`).
- **Tier 1 (Panels & Card Containers):** Crisp 1px solid perimeter boundary (`#C9DCDC` / `#1F383B`) backed by pure surface fills. Shadows are limited to a 1px offset line: `0 1px 2px rgba(15, 59, 63, 0.05)`.
- **Tier 2 (Popovers, Flyout Tooltips, Digest Previews):** Hardened structural edge with an ultra-subtle directional wash: `0 4px 12px -2px rgba(15, 59, 63, 0.12), 0 0 0 1px rgba(15, 59, 63, 0.08)`.
- **Tier 3 (Safety Gate Drawer / Authorize Confirmation Modal):** Heavy scrim overlay (`rgba(11, 25, 27, 0.72)`) paired with a high-contrast container framed by a 2px boundary.

Interactive hover states avoid floating up; they respond by shifting their border value closer to the primary brand ink (`#006D77`) or adjusting surface values by a 3% delta.

## Shapes

The design system enforces a `Soft` (Option 1) geometric profile. The corners reflect an engineered, industrial piece of precision equipment:

- **Buttons, Inputs, Badges, Tabs:** `0.25rem` (4px).
- **Cards, Audit Containers, Diff Blocks:** `0.5rem` (8px).
- **Modals, Safety Drawers:** `0.75rem` (12px).
- **Pills / Status Dots:** Fully rounded (`9999px`) exclusively reserved for live connection status beacons and countdown progress indicators.

Rounded geometries must never approach bubbly, organic, or pill-heavy aesthetics. Sharp structural edges communicate immutability and mechanical stability.

## Components

### Buttons & Authorization Controls
- **Primary Authorization ("ALLOW"):** Background `#1B6E48`, text `#FFFFFF`, border 1px solid transparent. On hover: darkened to `#145537`. Focus ring: 2px offset ring in `#1B6E48`.
- **Primary Rejection ("DENY"):** Background `#A33B3B`, text `#FFFFFF`, border 1px solid transparent. On hover: `#822D2D`.
- **Secondary Actions:** White or dark slate surface with 1px border (`#C9DCDC`), text `#0F3B3F`, sans-serif 14px weight 600.
- **Fail-Closed Manual Trip:** Hatched warning border with `#6E1A24` text and an explicit confirmation slide interaction to prevent accidental actuation.

### Badges & Governance Indicators
- Rendered in `JetBrains Mono`, 11px uppercase with `0.04em` tracking.
- Composed with a 1px border and a matching 10% tinted background.
  - `ALLOW`: Green border (`#1B6E48`), background `#E8F4EE`, text `#1B6E48`.
  - `DENY`: Crimson border (`#A33B3B`), background `#FBEAEA`, text `#A33B3B`.
  - `UNTRUSTED`: High-contrast Crimson text with a warning prefix icon.
  - `TRUSTED ADAPTER`: Cyan-slate border (`#2A5C74`), background `#EBF2F7`, text `#2A5C74`.
  - `FAIL CLOSED`: Dark cherry background (`#6E1A24`), text `#FFFFFF`.

### Cryptographic Components
- **DigestChip:** Displays a truncated cryptographic hash (e.g., `sha256:4a8f…90bc`). Monospace font, 12px. Inset container styling with a muted copy icon. Clicking triggers an instant inline checkmark with a transient tooltip ("Hash verified & copied to clipboard").
- **CopyableMono:** Compact snippet box featuring numeric line reference indicators, syntax-highlighted JSON strings, and a discrete top-right copy utility.

### Action Comparison Diff Rows
- Side-by-side or stacked split grid comparing `Proposed Agent Args` (left/top) versus `Trusted Adapter Preview` (right/bottom).
- Unaltered properties: muted ink on neutral canvas.
- Mutated/Dangerous properties: flagged with a tinted background (`#FEF6EB` for deviations, `#FBEAEA` for unauthorized parameter injections) with bold monospace tokens and visual callout markers.

### Countdown Timer & Safety Drawer
- **Approval Timer:** Depicts an expiring authorization window. Uses a persistent countdown ticker in tabular monospace, paired with a non-distracting linear hairline progress bar. When < 10 seconds remain, the progress bar transitions to Ochre Amber (`#C47A1E`).
- **Safety Gate Drawer:** Slides out from the right viewport boundary (480px width desktop). Houses cryptographic signature checks, authorization policy paths, agent capability scopes, and binary arbitration triggers.

### Gateway Status Indicator
- Compact status pill located in the global utility header.
- **Normal:** Solid emerald beacon dot (`#1B6E48`) paired with text `FAIL CLOSED: ARMED (OK)`.
- **Unreachable / Interrupted:** Pulsing warning beacon (`#6E1A24`) paired with `GATEWAY UNREACHABLE: SINK ACTIVE`. All forward arbitration action buttons instantly disable into fail-closed lock states.