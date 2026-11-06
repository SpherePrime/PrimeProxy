const { app, BrowserWindow } = require("electron");
const os = require("os");
const fs = require("fs");
const path = require("path");

const root = path.join(__dirname, "..");
const outDir = path.join(root, "build");
const fontDir = path.join(root, "node_modules", "@fontsource-variable", "inter", "files");
const version = require(path.join(root, "package.json")).version;

const fontFace = ["latin", "cyrillic"]
  .map(
    (subset) =>
      `@font-face{font-family:Inter;font-weight:100 900;src:url("file:///${path
        .join(fontDir, `inter-${subset}-wght-normal.woff2`)
        .replace(/\\/g, "/")}") format("woff2");}`,
  )
  .join("");

const mark = (size) => `
<svg width="${size}" height="${size}" viewBox="0 0 36 36" style="overflow:visible;filter:drop-shadow(0 0 ${Math.round(size / 5)}px rgba(255,106,53,.55))">
  <g transform="translate(8 2) skewX(-20)" fill="#ff6a35">
    <rect y="7" width="7" height="22" rx="2"/><rect x="11" width="7" height="32" rx="2"/><rect x="22" y="7" width="7" height="22" rx="2"/>
  </g>
</svg>`;

const base = `${fontFace}*{margin:0;box-sizing:border-box}html,body{width:100%;height:100%;overflow:hidden;font-family:Inter,"Segoe UI",sans-serif;-webkit-font-smoothing:antialiased}`;

const grid = `background-image:linear-gradient(rgba(255,255,255,.045) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.045) 1px,transparent 1px);background-size:14px 14px;`;

const pages = {
  icon: {
    width: 256,
    height: 256,
    html: `<style>${base}body{background:transparent;display:grid;place-items:center}
      .tile{width:240px;height:240px;border-radius:58px;display:grid;place-items:center;position:relative;overflow:hidden;
        background:radial-gradient(120% 120% at 85% 0%,rgba(255,106,53,.38),transparent 55%),linear-gradient(160deg,#202020,#0c0c0c);
        box-shadow:inset 0 2px 0 rgba(255,255,255,.08),inset 0 0 0 2px rgba(255,255,255,.05)}
      .tile svg{transform:translateX(-6px)}</style>
      <div class="tile">${mark(150)}</div>`,
  },
  sidebar: {
    width: 164,
    height: 314,
    html: `<style>${base}body{background:#0d0d0d;color:#f1efe9;position:relative}
      .grid{position:absolute;inset:0;${grid}-webkit-mask-image:radial-gradient(ellipse 120% 70% at 80% 0%,#000 20%,transparent 75%)}
      .glow{position:absolute;width:320px;height:320px;top:-170px;right:-170px;border-radius:50%;background:radial-gradient(circle,rgba(255,106,53,.55),transparent 62%);filter:blur(6px)}
      .glow2{position:absolute;width:260px;height:260px;bottom:-190px;left:-120px;border-radius:50%;background:radial-gradient(circle,rgba(255,106,53,.18),transparent 65%)}
      .content{position:absolute;inset:0;padding:26px 18px 20px;display:flex;flex-direction:column}
      .name{margin-top:18px;font-size:23px;font-weight:500;letter-spacing:-.04em;line-height:1}
      .name b{font-weight:800}
      .eyebrow{margin-top:12px;display:flex;align-items:center;gap:7px;font:600 8.5px/1.2 "Cascadia Mono",Consolas,monospace;letter-spacing:.16em;color:#8d8a84;text-transform:uppercase}
      .eyebrow i{width:5px;height:5px;border-radius:1.5px;background:#ff6a35;box-shadow:0 0 8px #ff6a35;flex-shrink:0}
      .lead{margin-top:auto;font-size:12.5px;line-height:1.45;color:#b9b6af;font-weight:500}
      .lead em{font-style:normal;color:#ff6a35;font-weight:700}
      .ver{margin-top:14px;font:500 9px/1 Consolas,monospace;color:#5f5d59;letter-spacing:.1em}</style>
      <div class="grid"></div><div class="glow"></div><div class="glow2"></div>
      <div class="content">${mark(46)}
        <div class="name"><b>Prime</b>Bypass</div>
        <div class="eyebrow"><i></i>обход блокировок</div>
        <div class="lead">YouTube, Discord, Telegram и&nbsp;остальное — <em>одной кнопкой</em>.</div>
        <div class="ver">VERSION ${version}</div>
      </div>`,
  },
  splash: {
    width: 480,
    height: 270,
    html: `<style>${base}body{background:#0d0d0d;color:#f1efe9;position:relative}
      .grid{position:absolute;inset:0;${grid}background-size:24px 24px;-webkit-mask-image:radial-gradient(ellipse 80% 90% at 85% 0%,#000 15%,transparent 75%)}
      .glow{position:absolute;width:520px;height:520px;top:-300px;right:-260px;border-radius:50%;background:radial-gradient(circle,rgba(255,106,53,.5),transparent 62%)}
      .content{position:absolute;inset:0;padding:40px 44px;display:flex;flex-direction:column}
      .row{display:flex;align-items:center;gap:16px}
      .name{font-size:34px;font-weight:500;letter-spacing:-.045em}.name b{font-weight:800}
      .eyebrow{margin-top:auto;display:flex;align-items:center;gap:9px;font:600 10px/1 Consolas,monospace;letter-spacing:.18em;color:#8d8a84;text-transform:uppercase}
      .eyebrow i{width:6px;height:6px;border-radius:2px;background:#ff6a35;box-shadow:0 0 10px #ff6a35}
      .bar{margin-top:14px;height:4px;border-radius:9px;background:rgba(255,255,255,.08);overflow:hidden}
      .bar span{display:block;width:62%;height:100%;border-radius:9px;background:linear-gradient(90deg,#ff9a5c,#ff6a35);box-shadow:0 0 12px #ff6a35}</style>
      <div class="grid"></div><div class="glow"></div>
      <div class="content"><div class="row">${mark(50)}<div class="name"><b>Prime</b>Bypass</div></div>
        <div class="eyebrow"><i></i>Подготовка установки…</div><div class="bar"><span></span></div></div>`,
  },
  header: {
    width: 150,
    height: 57,
    html: `<style>${base}body{background:#0d0d0d;color:#f1efe9;position:relative;display:flex;align-items:center;gap:9px;padding:0 14px}
      .glow{position:absolute;width:160px;height:160px;top:-100px;right:-70px;border-radius:50%;background:radial-gradient(circle,rgba(255,106,53,.45),transparent 62%)}
      svg{position:relative}.name{position:relative;font-size:16px;font-weight:500;letter-spacing:-.04em}.name b{font-weight:800}</style>
      <div class="glow"></div>${mark(26)}<div class="name"><b>Prime</b>Bypass</div>`,
  },
};

async function render(page) {
  const win = new BrowserWindow({
    show: false,
    width: page.width,
    height: page.height,
    useContentSize: true,
    transparent: true,
    frame: false,
    webPreferences: { offscreen: true },
  });
  win.webContents.setFrameRate(1);
  const file = path.join(os.tmpdir(), `primebypass-render-${page.width}x${page.height}.html`);
  fs.writeFileSync(file, `<!doctype html><meta charset="utf-8">${page.html}`);
  await win.loadFile(file);
  await win.webContents.executeJavaScript("document.fonts.ready.then(() => true)");
  await new Promise((resolve) => setTimeout(resolve, 400));
  const image = await win.webContents.capturePage();
  win.destroy();
  fs.unlinkSync(file);
  return image.resize({ width: page.width, height: page.height, quality: "best" });
}

function writeBmp(image, file) {
  const { width, height } = image.getSize();
  const bgra = image.toBitmap();
  const rowSize = Math.ceil((width * 3) / 4) * 4;
  const pixels = Buffer.alloc(rowSize * height);
  for (let y = 0; y < height; y += 1) {
    for (let x = 0; x < width; x += 1) {
      const source = (y * width + x) * 4;
      const target = (height - 1 - y) * rowSize + x * 3;
      pixels[target] = bgra[source];
      pixels[target + 1] = bgra[source + 1];
      pixels[target + 2] = bgra[source + 2];
    }
  }
  const header = Buffer.alloc(54);
  header.write("BM", 0);
  header.writeUInt32LE(54 + pixels.length, 2);
  header.writeUInt32LE(54, 10);
  header.writeUInt32LE(40, 14);
  header.writeInt32LE(width, 18);
  header.writeInt32LE(height, 22);
  header.writeUInt16LE(1, 26);
  header.writeUInt16LE(24, 28);
  header.writeUInt32LE(pixels.length, 34);
  header.writeInt32LE(2835, 38);
  header.writeInt32LE(2835, 42);
  fs.writeFileSync(file, Buffer.concat([header, pixels]));
}

function writeIco(image, file) {
  const sizes = [256, 128, 64, 48, 32, 24, 16];
  const pngs = sizes.map((size) => image.resize({ width: size, height: size, quality: "best" }).toPNG());
  const header = Buffer.alloc(6);
  header.writeUInt16LE(1, 2);
  header.writeUInt16LE(sizes.length, 4);
  const entries = Buffer.alloc(16 * sizes.length);
  let offset = 6 + entries.length;
  sizes.forEach((size, index) => {
    const entry = index * 16;
    entries[entry] = size === 256 ? 0 : size;
    entries[entry + 1] = size === 256 ? 0 : size;
    entries.writeUInt16LE(1, entry + 4);
    entries.writeUInt16LE(32, entry + 6);
    entries.writeUInt32LE(pngs[index].length, entry + 8);
    entries.writeUInt32LE(offset, entry + 12);
    offset += pngs[index].length;
  });
  fs.writeFileSync(file, Buffer.concat([header, entries, ...pngs]));
}

app.disableHardwareAcceleration();
app.on("window-all-closed", () => {});
app.whenReady().then(async () => {
  fs.mkdirSync(outDir, { recursive: true });
  const icon = await render(pages.icon);
  fs.writeFileSync(path.join(outDir, "icon.png"), icon.toPNG());
  writeIco(icon, path.join(outDir, "icon.ico"));
  const sidebar = await render(pages.sidebar);
  writeBmp(sidebar, path.join(outDir, "installerSidebar.bmp"));
  fs.writeFileSync(path.join(outDir, "installerSidebar.png"), sidebar.toPNG());
  const header = await render(pages.header);
  writeBmp(header, path.join(outDir, "installerHeader.bmp"));
  fs.writeFileSync(path.join(outDir, "installerHeader.png"), header.toPNG());
  const splash = await render(pages.splash);
  writeBmp(splash, path.join(outDir, "splash.bmp"));
  fs.writeFileSync(path.join(outDir, "splash.png"), splash.toPNG());
  app.quit();
});
