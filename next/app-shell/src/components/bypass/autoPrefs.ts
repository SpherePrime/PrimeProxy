const AUTO_MODE_KEY = "pp.auto";
const WITH_TELEGRAM_KEY = "pp.auto.tg";

function readFlag(key: string, fallback: boolean): boolean {
  try {
    const value = localStorage.getItem(key);
    return value === null ? fallback : value === "1";
  } catch {
    return fallback;
  }
}

function writeFlag(key: string, value: boolean): void {
  try {
    localStorage.setItem(key, value ? "1" : "0");
  } catch {
    return;
  }
}

export const readAutoMode = () => readFlag(AUTO_MODE_KEY, true);
export const saveAutoMode = (value: boolean) => writeFlag(AUTO_MODE_KEY, value);
export const readWithTelegram = () => readFlag(WITH_TELEGRAM_KEY, true);
export const saveWithTelegram = (value: boolean) => writeFlag(WITH_TELEGRAM_KEY, value);
