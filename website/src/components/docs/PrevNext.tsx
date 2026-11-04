import Link from "next/link";

type PageLink = { href: string; label: string };

export default function PrevNext({ prev, next }: { prev?: PageLink; next?: PageLink }) {
    if (!prev && !next) return null;
    const card = "flex-1 rounded-xl border border-border p-4 transition-colors hover:border-accent";
    return (
        <nav aria-label="Previous and next" className="mt-16 flex flex-col gap-4 border-t border-border pt-8 sm:flex-row">
            {prev ? (
                <Link href={prev.href} className={card}>
                    <span className="text-sm text-muted">← Previous</span>
                    <span className="mt-1 block font-semibold text-fg">{prev.label}</span>
                </Link>
            ) : (
                <span className="flex-1" />
            )}
            {next && (
                <Link href={next.href} className={`${card} text-right`}>
                    <span className="text-sm text-muted">Next →</span>
                    <span className="mt-1 block font-semibold text-fg">{next.label}</span>
                </Link>
            )}
        </nav>
    );
}
