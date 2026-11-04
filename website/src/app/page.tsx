import Image from "next/image";
import Link from "next/link";
import DocPage from "@/components/docs/DocPage";
import { getLevels, getSiteIntro } from "@/lib/content";
import type { Heading } from "@/lib/markdown";

export default function Home() {
    const levels = getLevels();
    const topics = levels.flatMap((l) => l.topics);
    const ready = topics.filter((t) => t.hasNotes).length;

    const toc: Heading[] = [
        { id: "overview", text: "Overview", depth: 2 },
        { id: "how-to-use", text: "How to use this course", depth: 2 },
        { id: "learning-path", text: "Learning path", depth: 2 },
        ...levels.map((l) => ({ id: `level-${l.number}`, text: `${l.number}. ${l.title}`, depth: 3 })),
    ];

    const baseUrl = process.env.NEXT_PUBLIC_APP_URL || "http://localhost:3000";
    const jsonLd = {
        "@context": "https://schema.org",
        "@graph": [
            { "@type": "WebSite", name: "Auth Mastery", url: baseUrl, inLanguage: "en" },
            {
                "@type": "Course",
                name: "Authentication Mastery",
                description:
                    "Backend authentication and authorization, level by level: passwords, sessions, cookies, JWT, OAuth, MFA and enterprise SSO.",
                url: baseUrl,
                isAccessibleForFree: true,
                inLanguage: "en",
                provider: { "@type": "Person", name: "Ashutosh Kumar" },
                hasCourseInstance: { "@type": "CourseInstance", courseMode: "online", courseWorkload: "PT20H" },
                offers: { "@type": "Offer", price: 0, priceCurrency: "USD", category: "Free" },
                syllabusSections: levels.map((l) => ({
                    "@type": "Syllabus",
                    name: `Level ${l.number}: ${l.title}`,
                    url: `${baseUrl}${l.href}`,
                })),
            },
        ],
    };

    return (
        <DocPage toc={toc}>
            <script
                type="application/ld+json"
                dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd).replace(/</g, "\\u003c") }}
            />
            <div id="overview" className="scroll-mt-24">
                <Image
                    src="/content/resources/banner.svg"
                    alt="Authentication Mastery: backend auth, level by level, from passwords to enterprise SSO"
                    width={1280}
                    height={400}
                    priority
                    unoptimized
                    className="w-full rounded-2xl border border-border"
                />
                <h1 className="mt-10 text-3xl font-bold tracking-tight sm:text-4xl">Authentication Mastery</h1>
                <hr className="my-8 border-border" />
                <p className="text-lg leading-relaxed text-muted">
                    <strong className="text-fg">
                        Learn backend authentication step by step, in plain English, with runnable Node.js examples.
                    </strong>{" "}
                    {getSiteIntro()} Every lesson comes with beginner-friendly notes, visual diagrams and code you
                    can run.
                </p>
                <div className="mt-6 flex flex-wrap gap-3 text-sm">
                    {[`${levels.length} levels`, `${topics.length} topics`, `${ready} ready to read`].map((s) => (
                        <span key={s} className="rounded-full border border-border bg-surface px-3 py-1 font-medium">
                            {s}
                        </span>
                    ))}
                </div>
            </div>

            <section id="how-to-use" className="mt-10 scroll-mt-24 rounded-xl border-l-4 border-accent bg-accent-soft p-6">
                <p className="text-lg font-semibold text-accent">🚀 Tip</p>
                <h2 className="mt-2 text-xl font-bold">How to use this course</h2>
                <ol className="mt-3 list-decimal space-y-2 pl-5 leading-relaxed">
                    <li>Go through the levels <strong>in order</strong>. Each one builds on the previous.</li>
                    <li>
                        Read a topic&apos;s <strong>notes</strong>: real-life examples, step-by-step explanations,
                        common mistakes and interview questions.
                    </li>
                    <li>
                        Look at the <strong>📊 diagrams</strong> to see every flow visually.
                    </li>
                    <li>
                        Run the <strong>💻 code</strong>: clone the repo, open the topic folder and run{" "}
                        <code className="rounded bg-surface px-1.5 py-0.5 font-mono text-sm">node server.js</code>.
                    </li>
                </ol>
            </section>

            <section id="learning-path" className="mt-14 scroll-mt-24">
                <h2 className="text-3xl font-bold tracking-tight">Learning path</h2>
                <p className="mt-2 text-muted">From the very basics to enterprise SSO, in 9 levels.</p>

                <div className="mt-8 space-y-6">
                    {levels.map((level) => {
                        const done = level.topics.filter((t) => t.hasNotes).length;
                        return (
                            <div
                                key={level.slug}
                                id={`level-${level.number}`}
                                className="scroll-mt-24 rounded-2xl border border-border bg-surface p-6"
                            >
                                <div className="flex flex-wrap items-baseline justify-between gap-2">
                                    <Link href={level.href} className="group">
                                        <span className="block font-mono text-xs tracking-widest text-accent uppercase">
                                            Level {level.number}
                                        </span>
                                        <span className="text-xl font-bold group-hover:text-accent">{level.title}</span>
                                    </Link>
                                    <span className="text-sm text-muted">
                                        {done}/{level.topics.length} ready
                                    </span>
                                </div>
                                <div className="mt-3 h-1.5 overflow-hidden rounded-full bg-hover" aria-hidden>
                                    <div
                                        className="h-full rounded-full bg-accent"
                                        style={{ width: `${(done / level.topics.length) * 100}%` }}
                                    />
                                </div>
                                <ul className="mt-4 grid gap-1 sm:grid-cols-2">
                                    {level.topics.map((t) => (
                                        <li key={t.slug}>
                                            <Link
                                                href={t.href}
                                                className={`flex gap-2 rounded-lg px-2 py-1.5 hover:bg-hover ${t.hasNotes ? "text-fg" : "text-muted"}`}
                                            >
                                                <span className="font-mono text-sm opacity-70">{t.number}</span>
                                                <span className="flex-1">{t.title}</span>
                                                <span aria-label={t.hasNotes ? "ready" : "coming soon"}>
                                                    {t.hasNotes ? "✅" : "⏳"}
                                                </span>
                                            </Link>
                                        </li>
                                    ))}
                                </ul>
                            </div>
                        );
                    })}
                </div>
            </section>
        </DocPage>
    );
}
