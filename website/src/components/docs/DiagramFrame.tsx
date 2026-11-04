"use client";

import { useEffect, useRef, useState } from "react";
import { useResolvedTheme } from "@/hooks/useResolvedTheme";

/**
 * Shows a topic's diagrams.html inside the page. The iframe grows to fit its content
 * and reloads with ?theme=... so the diagrams follow the site's light/dark switch.
 */
export default function DiagramFrame({ src, title }: { src: string; title: string }) {
    const theme = useResolvedTheme();
    // Starts small: the frame only ever grows to fit (scrollHeight never reports less than the frame)
    const [height, setHeight] = useState(400);
    const stopWatching = useRef<() => void>(undefined);

    useEffect(() => () => stopWatching.current?.(), []);

    if (!theme) return <div style={{ height }} className="rounded-xl border border-border bg-surface" />;

    return (
        <iframe
            key={theme}
            src={`${src}?theme=${theme}`}
            title={title}
            style={{ height }}
            className="block w-full rounded-xl border border-border bg-surface"
            onLoad={(e) => {
                stopWatching.current?.();
                const doc = e.currentTarget.contentDocument;
                if (!doc) return;
                // Mermaid draws after load, so keep matching the content's height as it changes
                // + 2 for the iframe's 1px top and bottom border (box-sizing: border-box)
                const fit = () => setHeight(doc.documentElement.scrollHeight + 2);
                const observer = new ResizeObserver(fit);
                observer.observe(doc.body);
                fit();
                stopWatching.current = () => observer.disconnect();
            }}
        />
    );
}
