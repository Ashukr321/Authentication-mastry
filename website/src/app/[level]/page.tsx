import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import DocPage from "@/components/docs/DocPage";
import PrevNext from "@/components/docs/PrevNext";
import { getLevel, getLevels } from "@/lib/content";

type Props = { params: Promise<{ level: string }> };

export const dynamicParams = false;

export function generateStaticParams() {
    return getLevels().map((l) => ({ level: l.slug }));
}

export async function generateMetadata({ params }: Props): Promise<Metadata> {
    const level = getLevel((await params).level);
    if (!level) return {};
    const title = `Level ${level.number}: ${level.title}`;
    const description = `${level.topics.length} topics: ${level.topics.map((t) => t.title).join(", ")}.`;
    return {
        title,
        description,
        alternates: { canonical: level.href },
        // A page-level openGraph replaces the root one, so the shared card image is listed again
        openGraph: { type: "website", siteName: "Auth Mastery", url: level.href, title, description, images: "/opengraph-image" },
    };
}

export default async function LevelPage({ params }: Props) {
    const level = getLevel((await params).level);
    if (!level) notFound();

    const levels = getLevels();
    const i = levels.indexOf(level);
    const label = (l: (typeof levels)[number]) => `Level ${l.number}: ${l.title}`;
    const done = level.topics.filter((t) => t.hasNotes).length;

    return (
        <DocPage toc={[]}>
            <p className="text-sm text-muted">
                <Link href="/" className="hover:text-accent">
                    Home
                </Link>{" "}
                › Level {level.number}
            </p>
            <h1 className="mt-2 text-4xl font-bold tracking-tight sm:text-5xl">
                <span className="block font-mono text-sm tracking-widest text-accent uppercase">
                    Level {level.number}
                </span>
                {level.title}
            </h1>
            <p className="mt-4 text-muted">
                {done} of {level.topics.length} topics ready.
            </p>

            <ol className="mt-8 space-y-3">
                {level.topics.map((t) => (
                    <li key={t.slug}>
                        <Link
                            href={t.href}
                            className="flex items-center gap-4 rounded-xl border border-border bg-surface p-4 transition-colors hover:border-accent"
                        >
                            <span className="font-mono text-lg font-bold text-accent">{t.number}</span>
                            <span className="flex-1">
                                <span className={`block font-semibold ${t.hasNotes ? "text-fg" : "text-muted"}`}>
                                    {t.title}
                                </span>
                                <span className="text-sm text-muted">
                                    {t.hasNotes
                                        ? ["📄 Notes", t.hasDiagrams && "📊 Diagrams", t.codeFiles.length > 0 && "💻 Code"]
                                              .filter(Boolean)
                                              .join(" · ")
                                        : "⏳ Coming soon"}
                                </span>
                            </span>
                            <span aria-hidden className="text-muted">
                                →
                            </span>
                        </Link>
                    </li>
                ))}
            </ol>

            <PrevNext
                prev={i > 0 ? { href: levels[i - 1].href, label: label(levels[i - 1]) } : undefined}
                next={i < levels.length - 1 ? { href: levels[i + 1].href, label: label(levels[i + 1]) } : undefined}
            />
        </DocPage>
    );
}
