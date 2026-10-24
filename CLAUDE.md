# Bounce Up

Social sport app for Melbourne's west (bounceup.app). Pickleball first, then badminton.

## How the code is laid out
- `index.html`: the whole app (one file: HTML, CSS and vanilla JS). No build step.
- `sw.js`: service worker (offline shell and phone notifications).
- `functions/_middleware.js`: Cloudflare Pages Function. Invite-only access code until the soft launch, and hides behind-the-scenes files.
- `privacy.html`, `terms.html`, `refunds.html`: legal pages (always public).
- Hosting: Cloudflare Pages deploys `main` automatically. Back end: Supabase.

## Rules
- Never put keys, passwords or the access code in this repo, in email or in chat. Secrets go straight into Supabase or Cloudflare settings.
- The back end (Supabase tables, functions, policies) belongs to Gaël. Front-end changes only here; back-end work goes on the `backend-setup` branch for him to apply.
- Test every change before pushing: the Playwright smoke and regression suites must pass, on phone, desktop and dark mode.
- Australian English, short plain sentences in anything users read. No invented numbers or testimonials.
- Players' photos only with permission; never label people by their job.
- Keep it fast: no new libraries unless there is no other way. Respect reduced motion.
