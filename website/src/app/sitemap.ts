import type { MetadataRoute } from "next";
import { getLevels } from "@/lib/content";

export default function sitemap(): MetadataRoute.Sitemap {
    const baseUrl = process.env.NEXT_PUBLIC_APP_URL || "http://localhost:3000";
    const levels = getLevels();

    return [
        { url: baseUrl, changeFrequency: "weekly", priority: 1 },
        ...levels.map((l) => ({ url: `${baseUrl}${l.href}`, changeFrequency: "weekly" as const, priority: 0.8 })),
        // Placeholder topics are noindex, so they stay out of the sitemap
        ...levels
            .flatMap((l) => l.topics)
            .filter((t) => t.hasNotes)
            .map((t) => ({ url: `${baseUrl}${t.href}`, changeFrequency: "weekly" as const, priority: 0.7 })),
    ];
}
