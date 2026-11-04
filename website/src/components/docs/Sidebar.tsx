"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState } from "react";
import type { NavLevel } from "@/types/nav";

const linkBase = "block rounded-lg px-3 py-1.5 text-[15px] transition-colors";

export default function Sidebar({ nav }: { nav: NavLevel[] }) {
    const pathname = usePathname();
    const currentLevel =
        nav.find(
            (l) => pathname === l.href || pathname.startsWith(`${l.href}/`),
        )?.href ?? null;

    // Accordion: only one level is open at a time
    const [openLevel, setOpenLevel] = useState(currentLevel);
    const [lastLevel, setLastLevel] = useState(currentLevel);

    // Navigating into another level opens it (and closes the previous one)
    if (currentLevel !== lastLevel) {
        setLastLevel(currentLevel);
        if (currentLevel) setOpenLevel(currentLevel);
    }

    return (
        <nav aria-label="Course" className="flex flex-col gap-1 p-4">
            <Link
                href="/"
                aria-current={pathname === "/" ? "page" : undefined}
                className={`${linkBase} text-base font-semibold ${pathname === "/" ? "bg-accent-soft text-accent" : "text-fg hover:bg-hover"}`}
            >
                🏠 Home
            </Link>

            {nav.map((level) => {
                const open = openLevel === level.href;
                const panelId = `level-panel-${level.number}`;
                const done = level.topics.filter((t) => t.done).length;
                const links = [
                    {
                        href: level.href,
                        label: "Overview",
                        number: "",
                        done: true,
                    },
                    ...level.topics.map((t) => ({
                        href: t.href,
                        label: t.title,
                        number: t.number,
                        done: t.done,
                    })),
                ];

                return (
                    <div key={level.href}>
                        <button
                            type="button"
                            aria-expanded={open}
                            aria-controls={panelId}
                            onClick={() =>
                                setOpenLevel(open ? null : level.href)
                            }
                            className={`hover:bg-hover flex w-full items-center justify-between rounded-lg px-3 py-2 text-left text-base font-semibold transition-colors ${
                                currentLevel === level.href
                                    ? "text-accent"
                                    : "text-fg"
                            }`}
                        >
                            <span>
                                <span className="text-muted block text-[11px] font-medium tracking-wider uppercase">
                                    Level {level.number} · {done}/
                                    {level.topics.length}
                                </span>
                                {level.title}
                            </span>
                            <span
                                aria-hidden
                                className={`text-muted text-lg transition-transform duration-300 ease-out motion-reduce:transition-none ${open ? "text-accent rotate-90" : ""}`}
                            >
                                ›
                            </span>
                        </button>

                        {/* Animates height from 0 to auto: grid rows 0fr -> 1fr */}
                        <div
                            id={panelId}
                            inert={!open}
                            className={`grid transition-[grid-template-rows,opacity] duration-300 ease-out motion-reduce:transition-none ${
                                open
                                    ? "grid-rows-[1fr] opacity-100"
                                    : "grid-rows-[0fr] opacity-0"
                            }`}
                        >
                            {/* The list's margins sit inside this clipping box, so a closed panel is truly 0px */}
                            <div className="min-h-0 overflow-hidden">
                                <ul className="border-border mt-1 mb-2 ml-3 border-l pl-2">
                                    {links.map((item, i) => {
                                        const active = pathname === item.href;
                                        return (
                                            <li
                                                key={item.href}
                                                // Links slide in one after another when the level opens
                                                style={{
                                                    transitionDelay: open
                                                        ? `${Math.min(i, 10) * 25}ms`
                                                        : "0ms",
                                                }}
                                                className={`transition-[opacity,translate] duration-300 ease-out motion-reduce:transition-none ${
                                                    open
                                                        ? "translate-x-0 opacity-100"
                                                        : "-translate-x-2 opacity-0"
                                                }`}
                                            >
                                                <Link
                                                    href={item.href}
                                                    aria-current={
                                                        active
                                                            ? "page"
                                                            : undefined
                                                    }
                                                    className={`${linkBase} flex items-baseline gap-2 ${
                                                        active
                                                            ? "bg-accent-soft text-accent font-semibold"
                                                            : item.done
                                                              ? "text-fg hover:bg-hover"
                                                              : "text-muted hover:bg-hover"
                                                    }`}
                                                >
                                                    {item.number && (
                                                        <span className="font-mono text-xs opacity-70">
                                                            {item.number}
                                                        </span>
                                                    )}
                                                    <span className="flex-1">
                                                        {item.label}
                                                    </span>
                                                    {!item.done && (
                                                        <span className="bg-hover rounded px-1.5 text-[10px] tracking-wide uppercase">
                                                            soon
                                                        </span>
                                                    )}
                                                </Link>
                                            </li>
                                        );
                                    })}
                                </ul>
                            </div>
                        </div>
                    </div>
                );
            })}
        </nav>
    );
}
