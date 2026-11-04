---
name: complete-topic
description: Complete a topic folder in Authentication-mastry (beginner README notes, an Express + Node.js server.js demo, and a diagrams.html page). Use when the user says "complete this" / "complete topic NN" / points at a level-*/NN-* folder.
---

# Complete a topic folder

Every topic folder (`level-N-*/NN-topic-name/`) ends up with:

```
README.md        # beginner notes (## Notes) + how to run the code (## Code)
server.js        # Express + Node.js demo, heavily commented
package.json     # only dependency: express ^5
diagrams.html    # Mermaid diagrams, separate from the README
```

Use the most recent finished topic (for example `level-2-account-lifecycle/12-email-verification`, `13-forgot-reset-password`) as the template for tone, structure and code style.

## 1. Code: Express + Node.js (required)

All example code is **Node.js with Express**. Don't use plain `http`, other frameworks, TypeScript or other languages.

- `package.json` in the topic folder: `"private": true`, `"scripts": { "start": "node server.js" }`, `"dependencies": { "express": "^5.1.0" }`. Run `npm install` there (`node_modules/` is git-ignored).
- CommonJS (`require`), one file, no build step. Add another dependency only when the topic is about that library (for example `jsonwebtoken` in Level 3).
- Use Node's built-in `crypto`: `randomBytes(32)` for tokens, `sha256` for storing tokens, `scrypt` + `timingSafeEqual` for passwords, `randomUUID()` for ids.
- "Database" = in-memory `Map`s with a `// shortcut:` comment saying a real app uses tables. Emails are printed with `console.log("📧 To: …")`.
- Standard skeleton: `express.json({ limit: "10kb" })`, `Cache-Control: no-store`, a 404 handler, and an error handler that maps `entity.parse.failed` → 400 and `entity.too.large` → 413 and never leaks stack traces.
- `PORT` comes from the environment (`Number(process.env.PORT) || 3000`). Port 3000 is often taken by the website dev server, so test on another port (for example `PORT=3013`). Links are built from a fixed `BASE_URL`, never the `Host` header.
- Comments explain **why**, in plain English, and follow the same numbered steps as the notes.
- **Run it and check every curl example** before finishing. Run the server as a background process and stop only that process. Never kill all `node` processes, because the user's website dev server is one of them.

## 2. README.md

- H1 is exactly `# NN. Title` (the website parses it).
- `## Notes`, for a beginner learning for a job switch:
  - "What is X?" with a bold **one-line answer** quote
  - Why it matters (a table of problems)
  - A real-life analogy (Indian names: Rahul, Priya; ₹)
  - `#### 📊 Diagrams` linking to `diagrams.html`, plus an "In short:" one-line flow
  - Step-by-step sections with small code snippets and ✅ Do / ❌ Don't tables
  - Tricky parts, **Common beginner mistakes** (numbered), **Interview questions** (with answers), **Quick recap**
  - Link related topics by number ("topic 09", "Level 6")
- `## Code`: a short intro, `📄 **Full code: [server.js](server.js)**`, `npm install` and `node server.js` blocks, a "Port 3000 busy?" tip, then `### Try it` with curl commands and the **real** output from your test run, and a PowerShell note at the end.
- Code lives in `server.js`, never inline in the README beyond small snippets.

## 3. diagrams.html

- Copy the structure of a finished topic's `diagrams.html`: `../../resources/diagrams.css`, the Mermaid UMD build from jsDelivr (`mermaid@11.4.1/dist/mermaid.min.js`), then `../../resources/diagrams.js`.
- At least a **flow diagram** (flowchart with `error` red / `ok` green / `trap` yellow classDefs) and a **data flow** (`sequenceDiagram` with real payloads, inside `class="layout wide"`). Each has a legend and a "How to read it" list.
- Escape `<br/>` and `-->` as `&lt;br/&gt;` / `--&gt;` inside `<pre class="mermaid">`.
- Mermaid gotchas: `"1. POST"` in a flowchart label renders as "Unsupported markdown: list" (write `"step 1: POST"`). A bare `https://…` renders as "Unsupported markdown: link" (drop the scheme). Two unconnected subgraphs stack badly: use two diagrams in `<div class="pair">`.
- Render-check it in the browser and search the page text for "Unsupported markdown" and "Syntax error".

## 4. Website

The `website/` Next.js app picks the topic up automatically when the conventions above are kept. Check the topic page at `http://localhost:3000/<level-folder>/<topic-folder>` if the dev server is running.

## 5. Finish

End the reply with a one-line commit message the user can copy, for example `docs(13): add forgot/reset password notes, Express server.js demo and diagrams page`. Don't commit unless asked.
