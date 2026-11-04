import type { MetadataRoute } from "next";

// Icons are generated from src/app/icon.svg by scripts/generate-icons.mjs
export default function manifest(): MetadataRoute.Manifest {
    return {
        id: "/",
        name: "Auth Mastery: backend authentication, level by level",
        short_name: "Auth Mastery",
        description:
            "Learn backend authentication and authorization step by step, in plain English.",
        start_url: "/",
        scope: "/",
        display: "standalone",
        orientation: "any",
        background_color: "#0f1733",
        theme_color: "#7c3aed",
        categories: ["education", "developer", "books"],
        lang: "en",
        icons: [
            { src: "/icon.svg", sizes: "any", type: "image/svg+xml" },
            { src: "/icons/icon-192.png", sizes: "192x192", type: "image/png", purpose: "any" },
            { src: "/icons/icon-512.png", sizes: "512x512", type: "image/png", purpose: "any" },
            { src: "/icons/maskable-192.png", sizes: "192x192", type: "image/png", purpose: "maskable" },
            { src: "/icons/maskable-512.png", sizes: "512x512", type: "image/png", purpose: "maskable" },
        ],
    };
}
