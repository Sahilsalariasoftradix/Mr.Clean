import {
  BrushCleaning,
  Cpu,
  FileText,
  FolderClosed,
  House,
  Package,
  Play,
  RefreshCw,
  Search,
  Settings as SettingsIcon,
  ShieldAlert,
  ShieldCheck,
  Trash2,
  type LucideIcon,
} from "lucide-react";
import { AnimatePresence, motion } from "motion/react";
import { useEffect, useMemo, useRef, useState } from "react";

import { bytes } from "../lib/format";
import { filter, type Command } from "../lib/palette";
import { words } from "../lib/platform";
import { useStore } from "../lib/store";
import { cx } from "./ui";

const isMac = typeof navigator !== "undefined" && /Mac/.test(navigator.platform || navigator.userAgent);
const mod = isMac ? "⌘" : "Ctrl+";
const OPEN_EVENT = "mrclean:palette";

/** Open the palette from anywhere (the sidebar's Search button). */
export function openPalette() {
  window.dispatchEvent(new Event(OPEN_EVENT));
}

export const paletteShortcut = `${mod}K`;

interface Item extends Command {
  icon: LucideIcon;
  run: () => void;
}

/** ⌘K / Ctrl+K: type to jump anywhere or run any action. */
export function CommandPalette() {
  const s = useStore();
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const input = useRef<HTMLInputElement>(null);
  const list = useRef<HTMLUListElement>(null);

  const openRef = useRef(false);
  // Opening and closing go through here so the "is it open" flag is right
  // even before React re-renders (keys typed straight after ⌘K count).
  const setShown = (next: boolean) => {
    openRef.current = next;
    setOpen(next);
    if (!next) {
      setQuery("");
      setActive(0);
    }
  };
  const setShownRef = useRef(setShown);
  setShownRef.current = setShown;

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((isMac ? e.metaKey : e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setShownRef.current(!openRef.current);
        return;
      }
      // Keys typed in the instant before the search box takes focus still count.
      const typing = e.key.length === 1 && !e.metaKey && !e.ctrlKey && !e.altKey;
      if (openRef.current && typing && e.target !== input.current) {
        e.preventDefault();
        setQuery((q) => q + e.key);
        setActive(0);
        input.current?.focus();
      }
    };
    const onOpen = () => setShownRef.current(true);
    window.addEventListener("keydown", onKey);
    window.addEventListener(OPEN_EVENT, onOpen);
    return () => {
      window.removeEventListener("keydown", onKey);
      window.removeEventListener(OPEN_EVENT, onOpen);
    };
  }, []);

  const items = useMemo<Item[]>(() => {
    const go = (id: Parameters<typeof s.go>[0], title: string, icon: LucideIcon, hint: string, keywords: string): Item => ({
      id: `go-${id}`,
      group: "Go to",
      title,
      icon,
      hint,
      keywords,
      run: () => s.go(id),
    });
    const out: Item[] = [
      go("overview", "Overview", House, `${mod}1`, "home dashboard health"),
      go("clean", "Clean", BrushCleaning, `${mod}2`, "caches junk xcode android npm"),
      go("files", "Files", FolderClosed, `${mod}3`, "large big folders disk space"),
      go("security", "Security", ShieldCheck, `${mod}4`, "threats protection findings"),
      go("memory", "Memory", Cpu, `${mod}5`, "ram processes apps"),
      go("settings", "Settings", SettingsIcon, `${mod},`, "preferences full disk access"),
      {
        id: "scan-all",
        group: "Actions",
        title: "Scan everything",
        icon: Play,
        keywords: "check all start",
        run: () => {
          s.go("overview");
          void s.scanEverything();
        },
      },
      { id: "scan-caches", group: "Actions", title: "Scan for developer caches", icon: BrushCleaning, keywords: "clean junk free space", run: () => s.request("clean", "scan") },
      { id: "find-nm", group: "Actions", title: "Find old node_modules", icon: Package, keywords: "npm projects free space", run: () => s.request("clean", "find_node_modules") },
      { id: "scan-files", group: "Actions", title: "Find large files", icon: FolderClosed, keywords: "big disk space scan home", run: () => s.request("files", "scan") },
      { id: "scan-security", group: "Actions", title: "Run security scan", icon: ShieldCheck, keywords: "malware threats virus check", run: () => s.request("security", "scan") },
      { id: "refresh-memory", group: "Actions", title: "Refresh memory usage", icon: RefreshCw, keywords: "ram processes", run: () => s.request("memory", "refresh") },
      s.deleteMode === "trash"
        ? {
            id: "mode-permanent",
            group: "Actions",
            title: "Delete permanently instead of using the " + words.trash,
            icon: Trash2,
            keywords: "delete mode setting",
            run: () => {
              s.setDeleteMode("permanent");
              s.toast("Cleaned items will now be deleted permanently.");
            },
          }
        : {
            id: "mode-trash",
            group: "Actions",
            title: `Move cleaned items to the ${words.trash}`,
            icon: Trash2,
            keywords: "delete mode setting undo",
            run: () => {
              s.setDeleteMode("trash");
              s.toast(`Cleaned items will now go to the ${words.trash}.`);
            },
          },
    ];

    // The latest scan results, so you can jump straight to one.
    for (const f of s.security?.findings ?? []) {
      if (f.severity !== "high" && f.severity !== "medium") continue;
      out.push({ id: `finding-${f.id}`, group: "Results", title: f.title, icon: ShieldAlert, hint: f.severity === "high" ? "High" : "Medium", keywords: `security ${f.area}`, run: () => s.go("security") });
    }
    for (const r of [...(s.cleaner?.rules ?? [])].filter((r) => r.total_bytes > 0).sort((a, b) => b.total_bytes - a.total_bytes).slice(0, 8)) {
      out.push({ id: `rule-${r.rule.id}`, group: "Results", title: r.rule.name, icon: BrushCleaning, hint: bytes(r.total_bytes), keywords: `clean cache ${r.rule.category}`, run: () => s.go("clean") });
    }
    for (const f of (s.files?.top_files ?? []).slice(0, 5)) {
      out.push({ id: `file-${f.path}`, group: "Results", title: f.name, icon: FileText, hint: bytes(f.bytes), keywords: `large file ${f.kind}`, run: () => s.go("files") });
    }
    return out;
  }, [s]);

  const shown = useMemo(() => filter(items, query), [items, query]);
  const current = Math.min(active, Math.max(0, shown.length - 1));

  useEffect(() => {
    list.current?.querySelector(`[data-index="${current}"]`)?.scrollIntoView({ block: "nearest" });
  }, [current]);

  const choose = (item: Item | undefined) => {
    if (!item) return;
    setShown(false);
    item.run();
  };

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setActive((a) => (shown.length ? (Math.min(a, shown.length - 1) + 1) % shown.length : 0));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setActive((a) => (shown.length ? (Math.min(a, shown.length - 1) - 1 + shown.length) % shown.length : 0));
    } else if (e.key === "Enter") {
      e.preventDefault();
      choose(shown[current]);
    } else if (e.key === "Escape") {
      e.preventDefault();
      setShown(false);
    }
  };

  return (
    <AnimatePresence>
      {open && (
        <motion.div
          className="fixed inset-0 z-50 flex justify-center bg-black/30 px-4 pt-[12vh] backdrop-blur-[3px]"
          onClick={() => setShown(false)}
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.12 }}
        >
          <motion.div
            role="dialog"
            aria-modal="true"
            aria-label="Command palette"
            className="h-fit w-full max-w-[560px] overflow-hidden rounded-[18px] border border-line bg-bg shadow-[0_30px_80px_-10px_rgba(0,0,0,0.45)]"
            onClick={(e) => e.stopPropagation()}
            initial={{ y: -12, scale: 0.98, opacity: 0 }}
            animate={{ y: 0, scale: 1, opacity: 1 }}
            exit={{ y: -8, scale: 0.98, opacity: 0 }}
            transition={{ duration: 0.16, ease: [0.2, 0.8, 0.2, 1] }}
          >
            <div className="flex items-center gap-3 border-b border-line px-4">
              <Search className="size-[18px] shrink-0 text-muted" aria-hidden />
              <input
                ref={input}
                autoFocus
                value={query}
                onChange={(e) => {
                  setQuery(e.target.value);
                  setActive(0);
                }}
                onKeyDown={onKeyDown}
                placeholder="Search pages, actions and scan results…"
                role="combobox"
                aria-expanded="true"
                aria-controls="palette-list"
                aria-activedescendant={shown[current] ? `palette-${current}` : undefined}
                className="h-14 flex-1 bg-transparent text-[15px] outline-none placeholder:text-faint"
                style={{ outline: "none" }}
              />
              <kbd className="rounded-[6px] border border-line px-1.5 py-0.5 text-[11px] text-faint">esc</kbd>
            </div>
            <ul ref={list} id="palette-list" role="listbox" aria-label="Results" className="max-h-[min(420px,55vh)] overflow-y-auto p-2">
              {shown.length === 0 && <li className="px-3 py-8 text-center text-[13px] text-muted">Nothing matches “{query}”.</li>}
              {shown.map((item, i) => {
                const header = i === 0 || shown[i - 1].group !== item.group;
                const Icon = item.icon;
                return (
                  <li key={item.id} role="presentation">
                    {header && <div className="px-3 pb-1 pt-2 text-[11px] font-semibold uppercase tracking-[0.08em] text-faint">{item.group}</div>}
                    <div
                      id={`palette-${i}`}
                      data-index={i}
                      role="option"
                      aria-selected={i === current}
                      onMouseMove={() => setActive(i)}
                      onClick={() => choose(item)}
                      className={cx("flex cursor-pointer items-center gap-3 rounded-[10px] px-3 py-2.5 text-[14px]", i === current && "bg-accent-soft text-accent-text")}
                    >
                      <Icon className={cx("size-4 shrink-0", i === current ? "text-accent-text" : "text-muted")} aria-hidden />
                      <span className="min-w-0 flex-1 truncate">{item.title}</span>
                      {item.hint && <span className="tabular shrink-0 text-[12px] text-faint">{item.hint}</span>}
                    </div>
                  </li>
                );
              })}
            </ul>
            <div className="flex items-center gap-4 border-t border-line px-4 py-2 text-[11.5px] text-faint">
              <span>↑↓ to move</span>
              <span>↵ to open</span>
              <span className="ml-auto">{paletteShortcut} anywhere</span>
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
