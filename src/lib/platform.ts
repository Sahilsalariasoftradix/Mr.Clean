import { inTauri } from "./api";
import { previewPlatform } from "./mock";

export type Platform = "mac" | "windows" | "linux";

export function detectPlatform(userAgent: string): Platform {
  if (/Windows/i.test(userAgent)) return "windows";
  if (/Mac/i.test(userAgent)) return "mac";
  return "linux";
}

/** The OS the app runs on. The browser preview uses the Mac mock data, so it says "mac". */
export const platform: Platform =
  inTauri && typeof navigator !== "undefined"
    ? detectPlatform(navigator.userAgent)
    : previewPlatform === "windows" || previewPlatform === "linux"
      ? previewPlatform
      : "mac";

export interface Words {
  /** "Mac" / "PC": "Your Mac, in good shape." */
  computer: string;
  /** "Mac" / "Windows" / "Linux": "Windows protection". */
  os: string;
  trash: string;
  /** Where "Show in …" opens a file. */
  fileManager: string;
  settingsApp: string;
  /** Where the status icon lives: "menu bar" / "system tray". */
  tray: string;
}

export function wordsFor(p: Platform): Words {
  switch (p) {
    case "windows":
      return { computer: "PC", os: "Windows", trash: "Recycle Bin", fileManager: "File Explorer", settingsApp: "Windows Settings", tray: "system tray" };
    case "linux":
      return { computer: "PC", os: "Linux", trash: "Trash", fileManager: "Files", settingsApp: "Settings", tray: "system tray" };
    default:
      return { computer: "Mac", os: "Mac", trash: "Trash", fileManager: "Finder", settingsApp: "System Settings", tray: "menu bar" };
  }
}

export const words = wordsFor(platform);
