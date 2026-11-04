import fs from "node:fs";
import path from "node:path";

// The notes live in the repo root, one folder above this Next.js app (website/).
export const CONTENT_ROOT = path.resolve(process.cwd(), "..");
export const REPO_URL =
    process.env.NEXT_PUBLIC_REPO_URL ??
    "https://github.com/Ashukr321/Authentication-mastry";

export type TopicMeta = {
    levelSlug: string;
    slug: string;
    number: string; // "06"
    title: string; // "Signup"
    href: string;
    hasNotes: boolean;
    hasDiagrams: boolean;
    codeFiles: string[]; // ["server.js"]
};

export type Level = {
    slug: string;
    number: number;
    title: string;
    href: string;
    topics: TopicMeta[];
};

const CODE_FILE = /\.(m?js|ts)$/;

// turbopackIgnore: pages are prerendered at build time, so the notes need not be bundled into the server
// (without it the whole repo gets traced into the deployment)
const read = (...parts: string[]) =>
    fs.readFileSync(/*turbopackIgnore: true*/ path.join(CONTENT_ROOT, ...parts), "utf8");

const subDirs = (dir: string, pattern: RegExp) =>
    fs
        .readdirSync(/*turbopackIgnore: true*/ path.join(CONTENT_ROOT, dir), { withFileTypes: true })
        .filter((d) => d.isDirectory() && pattern.test(d.name))
        .map((d) => d.name);

/** "level-1-basic-email-password" -> "Basic Email Password", used if the root README has no title for it. */
const humanize = (slug: string) =>
    slug
        .replace(/^(level-)?\d+-/, "")
        .split("-")
        .map((w) => w[0].toUpperCase() + w.slice(1))
        .join(" ");

/** Level titles come from the root README: "### [Level 0: Fundamentals](level-0-fundamentals)" */
function levelTitlesFromReadme() {
    const titles = new Map<string, string>();
    for (const m of read("README.md").matchAll(
        /^### \[Level \d+: (.+?)\]\((level-[^)]+)\)/gm,
    )) {
        titles.set(m[2], m[1]);
    }
    return titles;
}

/** A topic counts as written once its "## Notes" section has any content. */
export function hasNotesContent(markdown: string) {
    const notes = markdown.split(/^## Notes\s*$/m)[1]?.split(/^## /m)[0] ?? "";
    return notes.trim().length > 0;
}

function loadTopic(levelSlug: string, slug: string): TopicMeta {
    const readme = read(levelSlug, slug, "README.md");
    const h1 = readme.match(/^#\s+(\d+)\.\s+(.+)$/m);
    const files = fs.readdirSync(/*turbopackIgnore: true*/ path.join(CONTENT_ROOT, levelSlug, slug));
    return {
        levelSlug,
        slug,
        number: h1?.[1] ?? slug.split("-")[0],
        title: h1?.[2].trim() ?? humanize(slug),
        href: `/${levelSlug}/${slug}`,
        hasNotes: hasNotesContent(readme),
        hasDiagrams: files.includes("diagrams.html"),
        codeFiles: files.filter((f) => CODE_FILE.test(f)).sort(),
    };
}

let levelsCache: Level[] | undefined;

export function getLevels(): Level[] {
    // In dev, re-read every time so edits to the notes show up on refresh
    if (levelsCache && process.env.NODE_ENV === "production") return levelsCache;

    const titles = levelTitlesFromReadme();
    levelsCache = subDirs(".", /^level-\d+-/)
        .map((slug) => ({
            slug,
            number: Number(slug.match(/^level-(\d+)-/)![1]),
            title: titles.get(slug) ?? humanize(slug),
            href: `/${slug}`,
            topics: subDirs(slug, /^\d+-/)
                .sort()
                .map((topic) => loadTopic(slug, topic)),
        }))
        .sort((a, b) => a.number - b.number);
    return levelsCache;
}

export const getAllTopics = () => getLevels().flatMap((l) => l.topics);

export const getLevel = (slug: string) =>
    getLevels().find((l) => l.slug === slug);

export function getTopic(levelSlug: string, slug: string) {
    const level = getLevel(levelSlug);
    const meta = level?.topics.find((t) => t.slug === slug);
    if (!level || !meta) return undefined;
    return {
        level,
        meta,
        readme: read(levelSlug, slug, "README.md"),
        code: meta.codeFiles.map((name) => ({
            name,
            content: read(levelSlug, slug, name),
        })),
    };
}

/** The intro paragraph of the root README (the text right after the banner). */
export function getSiteIntro() {
    const lines = read("README.md").split("\n");
    const start = lines.findIndex((l) => l.startsWith("A level-by-level"));
    return start === -1 ? "" : lines[start];
}
