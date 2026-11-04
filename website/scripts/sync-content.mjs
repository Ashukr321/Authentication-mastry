// Copies every topic's diagrams.html and the shared resources/ folder from the repo
// into public/content, so the site can serve them. Runs before `dev` and `build`.
import fs from "node:fs";
import path from "node:path";

const repoRoot = path.resolve(import.meta.dirname, "..", "..");
const out = path.resolve(import.meta.dirname, "..", "public", "content");

const dirs = (dir, pattern) =>
    fs
        .readdirSync(dir, { withFileTypes: true })
        .filter((d) => d.isDirectory() && pattern.test(d.name))
        .map((d) => d.name);

fs.rmSync(out, { recursive: true, force: true });
fs.cpSync(path.join(repoRoot, "resources"), path.join(out, "resources"), { recursive: true });

let pages = 0;
for (const level of dirs(repoRoot, /^level-\d+-/)) {
    for (const topic of dirs(path.join(repoRoot, level), /^\d+-/)) {
        const file = path.join(repoRoot, level, topic, "diagrams.html");
        if (!fs.existsSync(file)) continue;
        fs.mkdirSync(path.join(out, level, topic), { recursive: true });
        fs.copyFileSync(file, path.join(out, level, topic, "diagrams.html"));
        pages++;
    }
}

console.log(`sync-content: copied resources/ and ${pages} diagrams.html pages into public/content`);
