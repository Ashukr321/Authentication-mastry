import path from "node:path";

export type ResolvedLink = { href: string; newTab: boolean };

const CODE_FILE = /\.(m?js|ts)$/;
const LEVEL_DIR = /^level-\d+-/;

// Ids of the sections the site adds under the notes. Prefixed so they can't clash with
// README heading ids (a README "#### 📊 Diagrams" heading already becomes "diagrams").
export const DIAGRAMS_ID = "topic-diagrams";
export const SOURCE_CODE_ID = "topic-source-code";

/** Anchor id used for a code file's section on a topic page, e.g. "server.js" -> "code-server-js". */
export const codeAnchor = (fileName: string) =>
    `code-${fileName.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`;

/**
 * Turns a link written inside a README into a URL on this site.
 * `fromDir` is the README's folder relative to the repo root, e.g. "level-1-basic-email-password/06-signup".
 */
export function resolveLink(
    href: string,
    fromDir: string,
    repoUrl: string,
): ResolvedLink {
    if (/^[a-z][a-z0-9+.-]*:/i.test(href)) return { href, newTab: true }; // https:, mailto:
    if (href.startsWith("#")) return { href, newTab: false };

    const [rawPath, hash] = href.split("#");
    const h = hash ? `#${hash}` : "";
    const target = path.posix
        .normalize(path.posix.join(fromDir, decodeURI(rawPath)))
        .replace(/\/$/, "");
    if (target.startsWith("..")) return { href, newTab: false };

    const parts = target === "." ? [] : target.split("/");
    const file = parts.at(-1) ?? "";

    if (parts.length === 0 || target === "README.md")
        return { href: `/${h}`, newTab: false };
    if (target.startsWith("resources/"))
        return { href: `/content/${target}${h}`, newTab: false };

    if (LEVEL_DIR.test(parts[0])) {
        const [level, topic] = parts;
        if (parts.length === 1 || (parts.length === 2 && file === "README.md"))
            return { href: `/${level}${h}`, newTab: false };
        if (parts.length === 2) return { href: `/${level}/${topic}${h}`, newTab: false };
        if (parts.length === 3 && file === "README.md")
            return { href: `/${level}/${topic}${h}`, newTab: false };
        if (parts.length === 3 && file === "diagrams.html")
            // a specific diagram opens the full page, otherwise jump to the embedded diagrams
            return hash
                ? { href: `/content/${target}${h}`, newTab: true }
                : { href: `/${level}/${topic}#${DIAGRAMS_ID}`, newTab: false };
        if (parts.length === 3 && CODE_FILE.test(file))
            return { href: `/${level}/${topic}#${codeAnchor(file)}`, newTab: false };
    }

    // Anything else (LICENSE, other files) is shown on GitHub
    return { href: `${repoUrl}/blob/main/${target}${h}`, newTab: true };
}

/** GitHub-style heading ids: "Step 1: Validate!" -> "step-1-validate", repeats get "-1", "-2". */
export function createSlugger() {
    const seen = new Map<string, number>();
    return (text: string) => {
        const base =
            text
                .toLowerCase()
                .replace(/[^\p{L}\p{N}\s-]/gu, "")
                .trim()
                .replace(/\s+/g, "-") || "section";
        const count = seen.get(base) ?? 0;
        seen.set(base, count + 1);
        return count ? `${base}-${count}` : base;
    };
}
