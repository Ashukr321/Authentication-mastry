import fs from "node:fs";
import path from "node:path";
import { ImageResponse } from "next/og";

export const alt = "Auth Mastery: backend authentication, level by level";
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

// The social preview card shared by every page (Open Graph + Twitter)
export default function OpengraphImage() {
    const icon = fs.readFileSync(path.join(process.cwd(), "src/app/icon.svg"), "base64");
    return new ImageResponse(
        (
            <div
                style={{
                    width: "100%",
                    height: "100%",
                    display: "flex",
                    alignItems: "center",
                    gap: 64,
                    padding: 80,
                    background: "linear-gradient(135deg, #070b1a 0%, #0f1733 55%, #1b0f2e 100%)",
                    color: "#ffffff",
                }}
            >
                {/* eslint-disable-next-line @next/next/no-img-element */}
                <img src={`data:image/svg+xml;base64,${icon}`} width={280} height={280} alt="" />
                <div style={{ display: "flex", flexDirection: "column", flex: 1, minWidth: 0 }}>
                    <div style={{ fontSize: 80, fontWeight: 800, letterSpacing: -2 }}>Auth Mastery</div>
                    <div
                        style={{
                            marginTop: 24,
                            height: 8,
                            width: 360,
                            borderRadius: 4,
                            background: "linear-gradient(90deg, #22d3ee, #a78bfa, #f472b6)",
                        }}
                    />
                    <div style={{ marginTop: 32, fontSize: 38, color: "#c7cbe0", lineHeight: 1.35 }}>
                        Backend authentication, level by level: passwords, sessions, JWT, OAuth, MFA and SSO.
                    </div>
                </div>
            </div>
        ),
        size,
    );
}
