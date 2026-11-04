import { describe, it, expect } from "vitest";
import { codeAnchor, createSlugger, resolveLink } from "@/lib/links";

const REPO = "https://github.com/me/repo";
const TOPIC = "level-1-basic-email-password/06-signup";

describe("resolveLink", () => {
    it("keeps external links and same-page anchors", () => {
        expect(resolveLink("https://nextjs.org", TOPIC, REPO)).toEqual({ href: "https://nextjs.org", newTab: true });
        expect(resolveLink("#step-1", TOPIC, REPO)).toEqual({ href: "#step-1", newTab: false });
    });

    it("turns code files into anchors on the topic page", () => {
        expect(resolveLink("server.js", TOPIC, REPO).href).toBe(`/${TOPIC}#code-server-js`);
    });

    it("sends diagrams.html to the embedded section, or the full page when a diagram is named", () => {
        expect(resolveLink("diagrams.html", TOPIC, REPO)).toEqual({ href: `/${TOPIC}#topic-diagrams`, newTab: false });
        expect(resolveLink("diagrams.html#scale", TOPIC, REPO)).toEqual({
            href: `/content/${TOPIC}/diagrams.html#scale`,
            newTab: true,
        });
    });

    it("maps topic and level folders (and their READMEs) to site routes", () => {
        expect(resolveLink("level-0-fundamentals/01-authentication-vs-authorization", "", REPO).href).toBe(
            "/level-0-fundamentals/01-authentication-vs-authorization",
        );
        expect(resolveLink("level-0-fundamentals", "", REPO).href).toBe("/level-0-fundamentals");
        expect(resolveLink("../07-login/README.md", TOPIC, REPO).href).toBe("/level-1-basic-email-password/07-login");
        expect(resolveLink("../../README.md", TOPIC, REPO).href).toBe("/");
    });

    it("serves resources from /content and other files from GitHub", () => {
        expect(resolveLink("resources/banner.svg", "", REPO).href).toBe("/content/resources/banner.svg");
        expect(resolveLink("LICENSE", "", REPO)).toEqual({ href: `${REPO}/blob/main/LICENSE`, newTab: true });
    });
});

describe("createSlugger", () => {
    it("makes GitHub-style ids and de-duplicates repeats", () => {
        const slug = createSlugger();
        expect(slug("Step 1: Validate & normalize!")).toBe("step-1-validate-normalize");
        expect(slug("🛡️ SameSite")).toBe("samesite");
        expect(slug("Notes")).toBe("notes");
        expect(slug("Notes")).toBe("notes-1");
    });

    it("builds code anchors", () => {
        expect(codeAnchor("server.js")).toBe("code-server-js");
    });
});
