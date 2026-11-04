"use client";

import { useRouter } from "next/navigation";
import { useEffect, useId, useMemo, useRef, useState } from "react";
import type { SearchItem } from "@/types/nav";

const MAX_RESULTS = 8;

function search(items: SearchItem[], query: string) {
    const words = query.toLowerCase().split(/\s+/).filter(Boolean);
    if (words.length === 0) return [];
    return items
        .filter((item) => {
            const text = `${item.title} ${item.context}`.toLowerCase();
            return words.every((w) => text.includes(w));
        })
        .slice(0, MAX_RESULTS);
}

const isTypingIn = (el: EventTarget | null) =>
    el instanceof HTMLElement && (el.isContentEditable || ["INPUT", "TEXTAREA", "SELECT"].includes(el.tagName));

export default function Search() {
    const router = useRouter();
    const listId = useId();
    const inputRef = useRef<HTMLInputElement>(null);
    const [items, setItems] = useState<SearchItem[] | null>(null);
    const [query, setQuery] = useState("");
    const [open, setOpen] = useState(false);
    const [active, setActive] = useState(0);

    const results = useMemo(() => search(items ?? [], query), [items, query]);

    // Press "/" anywhere to jump into the search box
    useEffect(() => {
        const onKey = (e: KeyboardEvent) => {
            if (e.key === "/" && !isTypingIn(e.target)) {
                e.preventDefault();
                inputRef.current?.focus();
            }
        };
        window.addEventListener("keydown", onKey);
        return () => window.removeEventListener("keydown", onKey);
    }, []);

    // The index is only downloaded the first time someone uses search
    const loadIndex = () => {
        if (items) return;
        fetch("/search-index.json")
            .then((r) => r.json())
            .then(setItems)
            .catch(() => setItems([]));
    };

    const go = (href: string) => {
        setOpen(false);
        setQuery("");
        inputRef.current?.blur();
        router.push(href);
    };

    const onKeyDown = (e: React.KeyboardEvent) => {
        if (e.key === "ArrowDown") {
            e.preventDefault();
            setActive((i) => Math.min(i + 1, results.length - 1));
        } else if (e.key === "ArrowUp") {
            e.preventDefault();
            setActive((i) => Math.max(i - 1, 0));
        } else if (e.key === "Enter" && results[active]) {
            go(results[active].href);
        } else if (e.key === "Escape") {
            setOpen(false);
            inputRef.current?.blur();
        }
    };

    const showList = open && query.trim().length > 0;

    return (
        <div className="relative w-full max-w-xs">
            <span aria-hidden className="pointer-events-none absolute top-1/2 left-3 -translate-y-1/2 text-muted">
                ⌕
            </span>
            <input
                ref={inputRef}
                type="search"
                role="combobox"
                aria-label="Search topics"
                aria-expanded={showList}
                aria-controls={listId}
                aria-activedescendant={showList && results[active] ? `${listId}-${active}` : undefined}
                placeholder="Search topics…"
                value={query}
                onFocus={() => {
                    loadIndex();
                    setOpen(true);
                }}
                onBlur={() => setOpen(false)}
                onChange={(e) => {
                    setQuery(e.target.value);
                    setActive(0);
                    setOpen(true);
                }}
                onKeyDown={onKeyDown}
                className="h-10 w-full rounded-lg border border-border bg-surface pr-10 pl-9 text-sm text-fg placeholder:text-muted focus:border-accent focus:outline-none"
            />
            <kbd className="pointer-events-none absolute top-1/2 right-3 -translate-y-1/2 rounded border border-border px-1.5 font-mono text-xs text-muted">
                /
            </kbd>

            {showList && (
                <ul
                    id={listId}
                    role="listbox"
                    className="absolute right-0 left-0 mt-2 max-h-96 overflow-y-auto rounded-xl border border-border bg-surface p-1 shadow-xl"
                >
                    {items === null && <li className="px-3 py-2 text-sm text-muted">Loading…</li>}
                    {items !== null && results.length === 0 && (
                        <li className="px-3 py-2 text-sm text-muted">No results for “{query}”</li>
                    )}
                    {results.map((r, i) => (
                        <li
                            key={r.href}
                            id={`${listId}-${i}`}
                            role="option"
                            aria-selected={i === active}
                            // mousedown (not click) so the input's blur doesn't close the list first
                            onMouseDown={(e) => {
                                e.preventDefault();
                                go(r.href);
                            }}
                            onMouseEnter={() => setActive(i)}
                            className={`cursor-pointer rounded-lg px-3 py-2 ${i === active ? "bg-accent-soft" : ""}`}
                        >
                            <div className="text-sm font-medium text-fg">
                                {r.title}
                                {r.soon && <span className="ml-2 text-xs text-muted">(coming soon)</span>}
                            </div>
                            <div className="text-xs text-muted">{r.context}</div>
                        </li>
                    ))}
                </ul>
            )}
        </div>
    );
}
