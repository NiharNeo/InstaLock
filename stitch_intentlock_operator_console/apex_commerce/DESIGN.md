---
name: Apex Commerce
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
  secondary: '#236863'
  on-secondary: '#ffffff'
  secondary-container: '#a9ece5'
  on-secondary-container: '#286d67'
  tertiary: '#743b24'
  on-tertiary: '#ffffff'
  tertiary-container: '#915239'
  on-tertiary-container: '#ffd7c9'
  error: '#ba1a1a'
  on-error: '#ffffff'
  error-container: '#ffdad6'
  on-error-container: '#93000a'
  primary-fixed: '#9ff0fb'
  primary-fixed-dim: '#82d3de'
  on-primary-fixed: '#001f23'
  on-primary-fixed-variant: '#004f56'
  secondary-fixed: '#acefe7'
  secondary-fixed-dim: '#90d3cb'
  on-secondary-fixed: '#00201e'
  on-secondary-fixed-variant: '#00504b'
  tertiary-fixed: '#ffdbce'
  tertiary-fixed-dim: '#ffb59a'
  on-tertiary-fixed: '#380d00'
  on-tertiary-fixed-variant: '#6f3720'
  background: '#eafdff'
  on-background: '#002022'
  surface-variant: '#c0eaef'
typography:
  headline-xl:
    fontFamily: Source Serif 4
    fontSize: 40px
    fontWeight: '600'
    lineHeight: 48px
  headline-xl-mobile:
    fontFamily: Source Serif 4
    fontSize: 30px
    fontWeight: '600'
    lineHeight: 38px
  headline-lg:
    fontFamily: Source Serif 4
    fontSize: 32px
    fontWeight: '600'
    lineHeight: 40px
  headline-lg-mobile:
    fontFamily: Source Serif 4
    fontSize: 24px
    fontWeight: '600'
    lineHeight: 32px
  headline-md:
    fontFamily: Source Serif 4
    fontSize: 24px
    fontWeight: '500'
    lineHeight: 32px
  headline-sm:
    fontFamily: Source Serif 4
    fontSize: 20px
    fontWeight: '500'
    lineHeight: 28px
  body-lg:
    fontFamily: Inter
    fontSize: 16px
    fontWeight: '400'
    lineHeight: 26px
  body-md:
    fontFamily: Inter
    fontSize: 14px
    fontWeight: '400'
    lineHeight: 22px
  body-sm:
    fontFamily: Inter
    fontSize: 13px
    fontWeight: '400'
    lineHeight: 18px
  body-bold:
    fontFamily: Inter
    fontSize: 14px
    fontWeight: '600'
    lineHeight: 22px
  code-lg:
    fontFamily: JetBrains Mono
    fontSize: 18px
    fontWeight: '500'
    lineHeight: 24px
  code-md:
    fontFamily: JetBrains Mono
    fontSize: 13px
    fontWeight: '500'
    lineHeight: 18px
  code-sm:
    fontFamily: JetBrains Mono
    fontSize: 11px
    fontWeight: '500'
    lineHeight: 16px
  label-caps:
    fontFamily: Inter
    fontSize: 11px
    fontWeight: '700'
    lineHeight: 14px
rounded:
  sm: 0.125rem
  DEFAULT: 0.25rem
  md: 0.375rem
  lg: 0.5rem
  xl: 0.75rem
  full: 9999px
spacing:
  gutter: 1.5rem
  gutter-mobile: 1rem
  margin: 2rem
  margin-mobile: 1rem
  space-xs: 0.25rem
  space-sm: 0.5rem
  space-md: 1rem
  space-lg: 1.5rem
  space-xl: 2.5rem
---

## Brand & Style

This design system establishes an authentic, high-trust storefront and customer self-service portal. It communicates financial certitude, operational transparency, and consumer dignity. Drawing from classical editorial commerce combined with high-precision transaction utilities, the aesthetic marries deliberate editorial craft with strict fintech accountability.

The visual execution relies on an organic warm parchment foundation, surgical line work, structured ink-slate typography, and deep aquatic teal accents. Interactions should feel deliberate, quiet, and stable—instilling confidence during payment authorization, transaction disputes, order locking, and refund tracking. It deliberately rejects noisy animations and aggressive micro-patterns in favor of immediate legibility, high-contrast clarity, and definitive state feedback.

## Colors

The palette is anchored in calming mineral and parchment tones, tuned to exceed WCAG AAA accessibility across key actions:

- **Canvas & Surface System:**
  - Base Canvas (`surface-ground`): `#FBF9F5` (warm, natural alabaster).
  - Raised Surface / Card Containers (`surface-card`): `#FFFFFF`.
  - Recessed / Inset Wells (`surface-sunken`): `#F7F4EC`.
  - Subtle Dividing Line (`border-subtle`): `#E8E2D5`.
  - Prominent / Structural Border (`border-strong`): `#D1C7B7`.

- **Brand & Accent Roles:**
  - Primary (`#006D77`): Deep maritime teal for main actions, active navigation states, verified seals, and primary keylines.
  - Secondary (`#83C5BE`): Soft seafoam used for subtle hover fills, badge backdrops, and active focus rings.
  - Tertiary / Intent Accent (`#E29578`): Terracotta peach for transaction alerts, intentional lock banners, and pending hold indicators.

- **Typography & Semantic Ink:**
  - Primary Ink (`#0F3B3F`): Deepest ink slate for primary titles, monetary digits, and critical content.
  - Muted Ink (`#3D5A5B`): Mid-tier slate for sub-labels, secondary metadata, and table column headers.
  - De-emphasized Ink (`#6E8282`): Low-emphasis metadata, timestamps, and placeholder copy.

- **Status & Trust Engine:**
  - Success / Settled: `#1B7340` on `#EBF7EE`.
  - Pending Hold / Intent-Locked: `#B25E00` on `#FFF6EB`.
  - Dispute / Critical Action: `#B3261E` on `#FDF2F2`.

## Typography

The type hierarchy segregates merchant storytelling, operational interface components, and auditable financial records:

- **Source Serif 4 (Headlines):** Used exclusively for editorial titles, storefront category heroes, brand reassurance statements, and support modal titles. It brings a grounded, literary authority that feels rooted and unhurried.
- **Inter (Interface & Body):** Used for navigation, product descriptions, form controls, labels, and standard customer communication. It provides neutral, uncompromised screen readability.
- **JetBrains Mono (Transactional Identifiers & Currencies):** Used for order references (`ORD-88219-X`), transaction hashes, webhook status tokens, lock countdown timers, tracking IDs, and all monetary values containing rupee/paise breakdowns (e.g., `₹14,499.50`). Monospaced alignment prevents tabular jitter when dynamic order updates refresh.

## Layout & Spacing

This design system uses a strict 12-column layout on desktop screens with a max-width container cap of `1280px` centered within the viewport. Spacing follows a modular 4px/8px rhythm:

- **Breakpoints:**
  - `Desktop`: 1024px and above (12 columns, 24px gutters, 32px canvas margins).
  - `Tablet`: 640px to 1023px (8 columns, 16px gutters, 24px canvas margins).
  - `Mobile`: Below 640px (4 columns, 16px gutters, 16px canvas margins).

- **Checkout & Portal Architecture:**
  - Storefront product grids operate on 3-column (desktop) or 1-column (mobile) flows.
  - Checkout and Customer Account Portal views transition into an intentional 8:4 split column. The primary pane (8 columns) delivers the line-item inspection and dispute workflows, while the fixed sticky panel (4 columns) anchors transaction summaries, customer support triggers, and Razorpay payment states.

## Elevation & Depth

To reinforce stability and avoid deceptive visual floating, this design system limits elevation to low-contrast boundaries and tight, warm-tinted contact shadows:

- **Level 0 (Flat / Sunken):** `#FBF9F5` or `#F7F4EC` surfaces with a 1px border of `#E8E2D5`. No box shadow. Used for read-only order details, itemized invoice tables, and code snippets.
- **Level 1 (Default Cards):** Pure `#FFFFFF` surface resting on `#FBF9F5`, framed by a 1px `#E8E2D5` structural border, accompanied by a subtle contact shadow: `0 1px 3px rgba(15, 59, 63, 0.04), 0 1px 2px rgba(15, 59, 63, 0.02)`.
- **Level 2 (Active Modals & Checkout Overlays):** `#FFFFFF` surface bordered by `#006D77` (at 20% opacity) with an elevation shadow of `0 10px 25px -5px rgba(15, 59, 63, 0.08), 0 8px 10px -6px rgba(15, 59, 63, 0.04)`.
- **Razorpay Modal Context:** When external payment frames open, the background is darkened with a warm neutral scrim: `#0F3B3F` at 40% opacity with a `backdrop-filter: blur(4px)` to isolate the secure checkout instance.

## Shapes

The design system maintains a refined, architectural curvature with a roundedness value of `1` (Soft):
- Standard elements (inputs, standard badges, and buttons) carry a `4px` (`0.25rem`) radius.
- Structural cards, invoice wrappers, and payment summary sheets carry an `8px` (`0.5rem`) radius.
- Deep nested containers within cards use a complementary `4px` radius to prevent visual nesting collision.
- Badges and monetary pills use an exact `9999px` full-pill contour when specifying dynamic status tags, ensuring they read distinctly from clickable interactive controls.

## Components

### Buttons
- **Primary Action (Payment, Confirm Intent):** Solid `#006D77` fill, text in `#FFFFFF` (Inter 14px SemiBold), 4px border radius. Height: 44px for accessible hit targets. Hover: `#0B565E`. Active/Pressed: `#09464C`. Focus-visible: 2px offset ring in `#83C5BE`.
- **Secondary / Support Action:** Transparent fill, 1px solid border in `#D1C7B7`, text in `#0F3B3F`. Hover: Background `#F7F4EC` with border color transitioning to `#006D77`.
- **Destructive / Dispute Action:** Background `#FFFFFF`, 1px solid `#F5C2C7`, text `#B3261E`. Hover: `#FDF2F2`.

### Inputs & Form Fields
- Surface: `#FFFFFF` with 1px border of `#D1C7B7`. Height: 44px, internal horizontal padding 14px.
- Text: `#0F3B3F` (Inter 14px Regular).
- Placeholder: `#6E8282`.
- Focus State: Border transitions to `#006D77` with a continuous subtle glow (`box-shadow: 0 0 0 3px rgba(131, 197, 190, 0.35)`).
- Error State: Border transitions to `#B3261E` with assistive error text in 12px Inter.

### Status Badges & Intent Chips
- Monospaced metadata chips use `JetBrains Mono` at 11px uppercase with `0.5px` tracking.
- **Intent-Locked Badge:** Background `#FFF6EB`, border `1px solid #FCD9B6`, text `#B25E00`. Prepended with an interlocking padlock micro-glyph.
- **Settled / Verified Badge:** Background `#EBF7EE`, border `1px solid #B7E4C7`, text `#1B7340`.
- **Razorpay Authorized Badge:** Background `#F0F9FA`, border `1px solid #BCE3E7`, text `#006D77`.

### Product & Order Cards
- Background `#FFFFFF`, 1px solid border `#E8E2D5`, 8px corner radius.
- Header block separates merchant details with a hairline horizontal rule (`#E8E2D5`).
- Order total is explicitly emphasized with `JetBrains Mono` bold typography alongside currency symbols (`₹`).

### Customer Support & Dispute Drawers
- Docked slide-over panel anchored to the right canvas margin, framed by an ink slate border.
- Features prominent state indicator headers: "Intent Protected", "Under Verification", or "Escalated to Merchant".
- Contains direct, single-click copy buttons adjacent to all transaction identifiers, automatically shifting to a checkmark confirmation upon touch.