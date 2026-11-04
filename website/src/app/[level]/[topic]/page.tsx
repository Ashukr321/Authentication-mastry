import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import DiagramFrame from "@/components/docs/DiagramFrame";
import DocPage from "@/components/docs/DocPage";
import PrevNext from "@/components/docs/PrevNext";
import { getAllTopics, getTopic, REPO_URL } from "@/lib/content";
import { codeAnchor, DIAGRAMS_ID, SOURCE_CODE_ID } from "@/lib/links";
import { highlight, renderMarkdown, type Heading } from "@/lib/markdown";

type Props = { params: Promise<{ level: string; topic: string }> };

export const dynamicParams = false;

export function generateStaticParams() {
    return getAllTopics().map((t) => ({ level: t.levelSlug, topic: t.slug }));
}

export async function generateMetadata({ params }: Props): Promise<Metadata> {
    const { level, topic } = await params;
    const meta = getTopic(level, topic)?.meta;
    if (!meta) return {};
    const title = `${meta.number}. ${meta.title}`;
    const description = `${meta.title}: beginner-friendly notes with real-life examples, diagrams, common mistakes and interview questions.`;
    return {
        title,
        description,
        alternates: { canonical: meta.href },
        // Placeholder topics stay out of search results until their notes are written
        robots: meta.hasNotes ? undefined : { index: false, follow: true },
        // A page-level openGraph replaces the root one, so the shared card image is listed again
        openGraph: { type: "article", siteName: "Auth Mastery", url: meta.href, title, description, images: "/opengraph-image" },
    };
}

export default async function TopicPage({ params }: Props) {
    const { level: levelSlug, topic: slug } = await params;
    const topic = getTopic(levelSlug, slug);
    if (!topic) notFound();

    const { level, meta, readme, code } = topic;
    const dir = `${levelSlug}/${slug}`;
    const githubUrl = `${REPO_URL}/tree/main/${dir}`;

    const notes = meta.hasNotes ? await renderMarkdown(readme, dir) : null;
    const files = await Promise.all(code.map(async (f) => ({ ...f, html: await highlight(f.content, "js") })));
    const showDiagrams = meta.hasNotes && meta.hasDiagrams;

    const toc: Heading[] = [
        ...(notes?.headings.filter((h) => h.depth <= 3) ?? []),
        ...(showDiagrams ? [{ id: DIAGRAMS_ID, text: "📊 Diagrams", depth: 2 }] : []),
        ...(files.length > 0
            ? [
                  { id: SOURCE_CODE_ID, text: "💻 Source code", depth: 2 },
                  ...files.map((f) => ({ id: codeAnchor(f.name), text: f.name, depth: 3 })),
              ]
            : []),
    ];

    const all = getAllTopics();
    const i = all.findIndex((t) => t.href === meta.href);
    const link = (t: (typeof all)[number]) => ({ href: t.href, label: `${t.number}. ${t.title}` });

    const baseUrl = process.env.NEXT_PUBLIC_APP_URL || "http://localhost:3000";
    const jsonLd = {
        "@context": "https://schema.org",
        "@graph": [
            {
                "@type": "TechArticle",
                headline: `${meta.number}. ${meta.title}`,
                url: `${baseUrl}${meta.href}`,
                isPartOf: { "@type": "Course", name: "Auth Mastery", url: baseUrl },
                educationalLevel: `Level ${level.number}: ${level.title}`,
                inLanguage: "en",
            },
            {
                "@type": "BreadcrumbList",
                itemListElement: [
                    { "@type": "ListItem", position: 1, name: "Home", item: baseUrl },
                    { "@type": "ListItem", position: 2, name: `Level ${level.number}: ${level.title}`, item: `${baseUrl}${level.href}` },
                    { "@type": "ListItem", position: 3, name: meta.title, item: `${baseUrl}${meta.href}` },
                ],
            },
        ],
    };

    return (
        <DocPage toc={toc}>
            <script
                type="application/ld+json"
                // Escape "<" so content can never close the script tag
                dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd).replace(/</g, "\\u003c") }}
            />
            <p className="text-sm text-muted">
                <Link href={level.href} className="hover:text-accent">
                    Level {level.number}: {level.title}
                </Link>{" "}
                › {meta.number}
            </p>
            <h1 className="mt-2 text-4xl font-bold tracking-tight sm:text-5xl">
                <span className="text-accent">{meta.number}.</span> {meta.title}
            </h1>

            {meta.hasNotes && (
                <div className="mt-6 flex flex-wrap gap-2 text-sm">
                    <a href="#notes" className="chip">📄 Notes</a>
                    {showDiagrams && <a href={`#${DIAGRAMS_ID}`} className="chip">📊 Diagrams</a>}
                    {files.map((f) => (
                        <a key={f.name} href={`#${codeAnchor(f.name)}`} className="chip">
                            💻 {f.name}
                        </a>
                    ))}
                    <a href={githubUrl} target="_blank" rel="noopener noreferrer" className="chip">
                        GitHub ↗
                    </a>
                </div>
            )}
            <hr className="my-8 border-border" />

            <div className="prose">
                {notes ? (
                    <div dangerouslySetInnerHTML={{ __html: notes.html }} />
                ) : (
                    <div className="rounded-2xl border border-dashed border-border bg-surface p-8 text-center">
                        <p className="text-4xl">⏳</p>
                        <p className="mt-3 text-xl font-semibold text-fg">Notes coming soon</p>
                        <p className="mt-2 text-muted">
                            This topic is on the roadmap. Follow the{" "}
                            <a href={githubUrl} target="_blank" rel="noopener noreferrer">
                                folder on GitHub
                            </a>{" "}
                            to see when it lands.
                        </p>
                    </div>
                )}

                {showDiagrams && (
                    <section>
                        <h2 id={DIAGRAMS_ID}>📊 Diagrams</h2>
                        <p>
                            The flow of this topic, drawn step by step.{" "}
                            <a href={`/content/${dir}/diagrams.html`} target="_blank" rel="noopener noreferrer">
                                Open them full screen ↗
                            </a>
                        </p>
                        <DiagramFrame src={`/content/${dir}/diagrams.html`} title={`${meta.title} diagrams`} />
                    </section>
                )}

                {files.length > 0 && (
                    <section>
                        <h2 id={SOURCE_CODE_ID}>💻 Source code</h2>
                        <p>
                            Clone the repo, then run it from the topic folder: <code>cd {dir}</code>
                        </p>
                        {files.map((f) => (
                            <div key={f.name} className="code-file">
                                <h3 id={codeAnchor(f.name)} className="code-file-header">
                                    <span>📄 {f.name}</span>
                                    <a href={`${REPO_URL}/blob/main/${dir}/${f.name}`} target="_blank" rel="noopener noreferrer">
                                        View on GitHub ↗
                                    </a>
                                </h3>
                                <div dangerouslySetInnerHTML={{ __html: f.html }} />
                            </div>
                        ))}
                    </section>
                )}
            </div>

            <PrevNext prev={i > 0 ? link(all[i - 1]) : undefined} next={i < all.length - 1 ? link(all[i + 1]) : undefined} />
        </DocPage>
    );
}
