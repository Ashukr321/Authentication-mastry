import { getLevels, getTopic } from "@/lib/content";
import { renderMarkdown } from "@/lib/markdown";
import type { SearchItem } from "@/types/nav";

// Built once at build time and served as a static file
export const dynamic = "force-static";

export async function GET() {
    const items: SearchItem[] = [];
    for (const level of getLevels()) {
        for (const t of level.topics) {
            const topicTitle = `${t.number}. ${t.title}`;
            items.push({ title: topicTitle, context: `Level ${level.number}: ${level.title}`, href: t.href, soon: !t.hasNotes });
            if (!t.hasNotes) continue;

            // Every "###" section of the notes is searchable too
            const { headings } = await renderMarkdown(getTopic(level.slug, t.slug)!.readme, `${level.slug}/${t.slug}`);
            for (const h of headings.filter((h) => h.depth === 3)) {
                items.push({ title: h.text, context: topicTitle, href: `${t.href}#${h.id}` });
            }
        }
    }
    return Response.json(items);
}
