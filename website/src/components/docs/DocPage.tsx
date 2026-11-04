import type { Heading } from "@/lib/markdown";
import Toc from "./Toc";

/** Page body: the content column, plus the sticky "On this page" column on wide screens. */
export default function DocPage({ toc, children }: { toc: Heading[]; children: React.ReactNode }) {
    return (
        <div className="flex gap-12 px-5 py-10 sm:px-8 lg:px-12">
            <article className="min-w-0 max-w-3xl flex-1">{children}</article>
            {toc.length > 0 && (
                <aside className="sticky top-24 hidden max-h-[calc(100vh-7rem)] w-64 shrink-0 self-start overflow-y-auto xl:block">
                    <Toc headings={toc} />
                </aside>
            )}
        </div>
    );
}
