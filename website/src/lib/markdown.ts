import { Marked } from "marked";
import { createHighlighter, type Highlighter } from "shiki";
import { REPO_URL } from "./content";
import { createSlugger, resolveLink } from "./links";

export type Heading = { id: string; text: string; depth: number };

const LANGS = ["js", "ts", "bash", "json", "html", "http", "sql"];
const THEMES = { light: "github-light", dark: "github-dark" } as const;

let highlighter: Promise<Highlighter> | undefined;
const getHighlighter = () =>
    (highlighter ??= createHighlighter({ themes: Object.values(THEMES), langs: LANGS }));

const escapeAttr = (s: string) =>
    s.replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;");

const toPlainText = (html: string) =>
    html
        .replace(/<[^>]+>/g, "")
        .replace(/&lt;/g, "<")
        .replace(/&gt;/g, ">")
        .replace(/&quot;/g, '"')
        .replace(/&#39;/g, "'")
        .replace(/&amp;/g, "&")
        .trim();

/** Syntax-highlighted HTML with both light and dark colors (switched by CSS). */
function codeHtml(h: Highlighter, code: string, lang = "") {
    const language = lang.split(/\s/)[0];
    return h.codeToHtml(code, {
        lang: LANGS.includes(language) ? language : "text",
        themes: THEMES,
        defaultColor: false,
    });
}

export const highlight = async (code: string, lang?: string) =>
    codeHtml(await getHighlighter(), code, lang);

/**
 * Renders one README to HTML. `fromDir` is its folder relative to the repo root,
 * used to turn relative links ("server.js", "../07-login") into site URLs.
 */
export async function renderMarkdown(markdown: string, fromDir: string) {
    const h = await getHighlighter();
    const slug = createSlugger();
    const headings: Heading[] = [];

    const marked = new Marked({
        gfm: true,
        renderer: {
            code({ text, lang }) {
                return codeHtml(h, text, lang);
            },
            heading({ tokens, depth }) {
                const inner = this.parser.parseInline(tokens);
                const text = toPlainText(inner);
                const id = slug(text);
                headings.push({ id, text, depth });
                return `<h${depth} id="${id}">${inner}<a class="anchor" href="#${id}" aria-label="Link to this section">#</a></h${depth}>\n`;
            },
            link({ href, title, tokens }) {
                const inner = this.parser.parseInline(tokens);
                const r = resolveLink(href, fromDir, REPO_URL);
                const titleAttr = title ? ` title="${escapeAttr(title)}"` : "";
                const tab = r.newTab ? ' target="_blank" rel="noopener noreferrer"' : "";
                return `<a href="${escapeAttr(r.href)}"${titleAttr}${tab}>${inner}</a>`;
            },
            image({ href, text }) {
                const r = resolveLink(href, fromDir, REPO_URL);
                return `<img src="${escapeAttr(r.href)}" alt="${escapeAttr(text)}" loading="lazy">`;
            },
        },
    });

    // The page shows the title itself, so drop the README's "# 06. Signup" line
    const body = markdown.replace(/^#\s+.+\n/, "");
    const html = await marked.parse(body);
    return { html, headings };
}
