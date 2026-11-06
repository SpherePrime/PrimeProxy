const fs = require("original-fs");
const path = require("path");

function listFiles(root) {
  const result = [];
  const walk = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else result.push(full);
    }
  };
  walk(root);
  return result;
}

function folderSizeKb(root) {
  return Math.round(listFiles(root).reduce((total, file) => total + fs.statSync(file).size, 0) / 1024);
}

async function copyTree(source, target, onProgress) {
  const files = listFiles(source);
  fs.mkdirSync(target, { recursive: true });
  let copied = 0;
  for (const file of files) {
    const relative = path.relative(source, file);
    const destination = path.join(target, relative);
    fs.mkdirSync(path.dirname(destination), { recursive: true });
    try {
      await fs.promises.copyFile(file, destination);
    } catch (error) {
      if (error.code === "EBUSY" || error.code === "EPERM") {
        throw new Error("PrimeBypass сейчас запущен. Закройте его и повторите установку.");
      }
      throw error;
    }
    copied += 1;
    onProgress(copied, files.length, relative);
  }
  return files.length;
}

function removePath(target) {
  fs.rmSync(target, { recursive: true, force: true });
}

module.exports = { listFiles, folderSizeKb, copyTree, removePath };
