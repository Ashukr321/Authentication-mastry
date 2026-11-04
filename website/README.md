# Auth Mastery website

The Next.js site that publishes the course in this repo: every `level-*/NN-topic/` folder becomes a page with its notes, diagrams and code.

Scaffolded with `nxt-init` (Next.js 16, React 19, Tailwind CSS 4, TypeScript, Vitest).

## How the content gets in

The notes are **not copied into this app**. At build time the site reads the repo root (one folder up):

| Source in the repo | Shown on the site as |
|---|---|
| `README.md` (root) | Level titles (`### [Level N: Title](level-…)`) and the intro on the home page |
| `level-*/NN-topic/README.md` | The topic page's notes. A topic with an empty `## Notes` section shows "Coming soon" |
| `level-*/NN-topic/*.js` | The "Source code" section, syntax highlighted |
| `level-*/NN-topic/diagrams.html` | The "Diagrams" section (embedded, follows the site's light/dark theme) |
| `resources/` | Shared files (banner, diagram styles) |

`scripts/sync-content.mjs` copies the `diagrams.html` pages and `resources/` into `public/content/` (git-ignored). It runs automatically before `npm run dev` and `npm run build`.

So to publish a new topic: write its README (and optional `server.js` / `diagrams.html`) in the repo, push, and the site rebuilds with it.

## Pages

| Route | Page |
|---|---|
| `/` | Home: banner, how to use the course, learning path |
| `/level-1-basic-email-password` | One level: its topics and progress |
| `/level-1-basic-email-password/06-signup` | One topic: notes, diagrams, source code |
| `/search-index.json` | Built at build time, used by the search box (press `/`) |

All pages are pre-rendered at build time (static HTML), so the site is fast and cheap to host.

## Run it locally

```bash
cd website
npm install
npm run dev
```

Open http://localhost:3000.

| Command | What it does |
|---|---|
| `npm run dev` | Dev server (re-reads the notes on every refresh) |
| `npm run build` | Production build (what Vercel runs) |
| `npm run start` | Serve the production build |
| `npm run lint` / `npm run typecheck` | ESLint / TypeScript checks |
| `npm run test:unit` | Vitest unit tests |

## Deploy to Vercel

1. Push this repo to GitHub (`Ashukr321/Authentication-mastry`).
2. On [vercel.com/new](https://vercel.com/new), **import** the repo.
3. In the import screen, set **Root Directory** to `website` (click *Edit* next to it). The framework is detected as Next.js automatically.
4. Leave **"Include files outside the root directory in the Build Step"** turned **on** (it's on by default). The site reads the notes from the repo root, one folder above `website/`.
5. Add an environment variable:
   - `NEXT_PUBLIC_APP_URL` = your site's URL, e.g. `https://auth-mastery.vercel.app` (used for the sitemap, robots.txt and social previews)
6. Click **Deploy**.

After that, every push to `main` redeploys the site, and pull requests get preview URLs.

Optional: `NEXT_PUBLIC_REPO_URL` changes the GitHub links (defaults to `https://github.com/Ashukr321/Authentication-mastry`).

## Notes

- The template's git hooks (husky) don't run here, because `website/` is a folder inside the main repo rather than its own git repo. `npm install` prints ".git can't be found", which is harmless.
- Node 20+ is required (see `.nvmrc`).
