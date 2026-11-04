"use client";

import { useEffect, useState } from "react";
import type { Heading } from "@/lib/markdown";

/** "On this page": links to the page's sections, highlighting the one being read. */
export default function Toc({ headings }: { headings: Heading[] }) {
    const [activeId, setActiveId] = useState(headings[0]?.id);

    useEffect(() => {
        const elements = headings
            .map((h) => document.getElementById(h.id))
            .filter((el): el is HTMLElement => el !== null);

        const observer = new IntersectionObserver(
            (entries) => {
                const visible = entries
                    .filter((e) => e.isIntersecting)
                    .sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top);
                if (visible[0]) setActiveId(visible[0].target.id);
            },
            // a heading counts as "current" while it's in the top 30% of the screen
            { rootMargin: "-72px 0px -70% 0px" },
        );
        elements.forEach((el) => observer.observe(el));
        return () => observer.disconnect();
    }, [headings]);

    return (
        <nav aria-label="On this page">
            <p className="mb-3 text-base font-semibold text-fg">On this page</p>
            <ul className="space-y-0.5 text-sm">
                {headings.map((h) => (
                    <li key={h.id} style={{ paddingLeft: `${(h.depth - 2) * 16}px` }}>
                        <a
                            href={`#${h.id}`}
                            aria-current={activeId === h.id ? "location" : undefined}
                            className={`block rounded-md px-2.5 py-1 leading-snug transition-colors ${
                                activeId === h.id
                                    ? "bg-accent font-medium text-accent-fg"
                                    : "text-muted hover:text-fg"
                            }`}
                        >
                            {h.text}
                        </a>
                    </li>
                ))}
            </ul>
        </nav>
    );
}
