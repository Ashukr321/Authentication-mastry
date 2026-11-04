"use client";

import { useEffect, useMemo, useState } from "react";
import type { Heading } from "@/lib/markdown";

/** "On this page": links to the page's sections, highlighting the one being read. Sections with sub-headings collapse. */
export default function Toc({ headings }: { headings: Heading[] }) {
    const [activeId, setActiveId] = useState(headings[0]?.id);
    const [closed, setClosed] = useState<ReadonlySet<string>>(new Set());

    // id of the top-level (h2) section each heading sits under; "" for top-level headings themselves
    const parents = useMemo(
        () =>
            headings.map((h, i) => {
                if (h.depth <= 2) return "";
                for (let j = i - 1; j >= 0; j--) if (headings[j].depth <= 2) return headings[j].id;
                return "";
            }),
        [headings],
    );
    const groups = useMemo(() => new Set(parents.filter(Boolean)), [parents]);

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

    const toggle = (id: string) =>
        setClosed((prev) => {
            const next = new Set(prev);
            if (!next.delete(id)) next.add(id);
            return next;
        });
    const allClosed = groups.size > 0 && [...groups].every((id) => closed.has(id));

    // when the current heading is inside a collapsed section, highlight the section instead
    const activeParent = parents[headings.findIndex((h) => h.id === activeId)];
    const highlighted = activeParent && closed.has(activeParent) ? activeParent : activeId;

    return (
        <nav aria-label="On this page">
            {groups.size > 0 && (
                <button
                    type="button"
                    onClick={() => setClosed(allClosed ? new Set() : new Set(groups))}
                    className="mb-2 px-2.5 text-xs font-medium text-muted hover:text-accent"
                >
                    {allClosed ? "Expand all" : "Collapse all"}
                </button>
            )}
            <ul className="space-y-0.5 text-[13px]">
                {headings.map((h, i) => {
                    if (parents[i] && closed.has(parents[i])) return null;
                    const isGroup = groups.has(h.id);
                    const open = !closed.has(h.id);
                    return (
                        <li key={h.id} className="flex items-start gap-0.5" style={{ paddingLeft: `${Math.max(h.depth - 2, 0) * 14}px` }}>
                            <a
                                href={`#${h.id}`}
                                aria-current={highlighted === h.id ? "location" : undefined}
                                className={`block min-w-0 flex-1 rounded-md px-2.5 py-1 leading-snug transition-colors ${
                                    highlighted === h.id ? "bg-accent font-medium text-accent-fg" : "text-muted hover:text-fg"
                                }`}
                            >
                                {h.text}
                            </a>
                            {isGroup && (
                                <button
                                    type="button"
                                    onClick={() => toggle(h.id)}
                                    aria-expanded={open}
                                    aria-label={`${open ? "Collapse" : "Expand"} ${h.text}`}
                                    className="grid h-6 w-6 shrink-0 place-items-center rounded text-xs text-muted hover:bg-surface hover:text-fg"
                                >
                                    <span aria-hidden className={`transition-transform ${open ? "rotate-90" : ""}`}>
                                        ›
                                    </span>
                                </button>
                            )}
                        </li>
                    );
                })}
            </ul>
        </nav>
    );
}
