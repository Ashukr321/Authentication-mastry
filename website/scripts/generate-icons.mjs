// Turns src/app/icon.svg into every PNG/ICO favicon and PWA icon. Run after changing the logo:
//   node scripts/generate-icons.mjs
import fs from "node:fs";
import path from "node:path";
import sharp from "sharp";

const root = path.resolve(import.meta.dirname, "..");
const svg = fs.readFileSync(path.join(root, "src/app/icon.svg"));
const png = (size) => sharp(svg, { density: 384 }).resize(size, size).png().toBuffer();

// Maskable: launchers crop to a circle, so keep the logo inside the 80% safe zone on a full-bleed background
const maskable = async (size) => {
    const inner = Math.round(size * 0.8);
    return sharp({ create: { width: size, height: size, channels: 4, background: "#0f1733" } })
        .composite([{ input: await png(inner), gravity: "center" }])
        .png()
        .toBuffer();
};

// ICO with embedded PNGs (supported by every current browser)
const ico = (images) => {
    const header = Buffer.alloc(6 + 16 * images.length);
    header.writeUInt16LE(1, 2);
    header.writeUInt16LE(images.length, 4);
    let offset = header.length;
    images.forEach(({ size, data }, i) => {
        const e = 6 + 16 * i;
        header.writeUInt8(size % 256, e);
        header.writeUInt8(size % 256, e + 1);
        header.writeUInt16LE(1, e + 4);
        header.writeUInt16LE(32, e + 6);
        header.writeUInt32LE(data.length, e + 8);
        header.writeUInt32LE(offset, e + 12);
        offset += data.length;
    });
    return Buffer.concat([header, ...images.map((i) => i.data)]);
};

const icons = path.join(root, "public/icons");
fs.mkdirSync(icons, { recursive: true });
fs.writeFileSync(path.join(root, "src/app/apple-icon.png"), await png(180));
fs.writeFileSync(path.join(icons, "icon-192.png"), await png(192));
fs.writeFileSync(path.join(icons, "icon-512.png"), await png(512));
fs.writeFileSync(path.join(icons, "maskable-192.png"), await maskable(192));
fs.writeFileSync(path.join(icons, "maskable-512.png"), await maskable(512));
fs.writeFileSync(
    path.join(root, "src/app/favicon.ico"),
    ico(await Promise.all([16, 32, 48].map(async (size) => ({ size, data: await png(size) })))),
);
console.log("generate-icons: wrote favicon.ico, apple-icon.png and public/icons/*.png");
