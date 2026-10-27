import { BellRing, CircleCheck, HardDrive, Lock, ShieldAlert, Trash2, type LucideIcon } from "lucide-react";
import { useEffect, useState, type ReactNode } from "react";

import { Button, Card, Checkbox, Page, Segmented, SoftTile, cx } from "../components/ui";
import { api, inTauri, openFullDiskAccessSettings } from "../lib/api";
import { ago } from "../lib/format";
import { fdaUiState, loadFdaDismissed, saveFdaDismissed } from "../lib/fda";
import { platform, words } from "../lib/platform";
import { useStore } from "../lib/store";
import type { AppIdentity, BackgroundSettings, DeleteMode, Schedule } from "../lib/types";

function Section({ icon, color, title, children }: { icon: LucideIcon; color: string; title: string; children: ReactNode }) {
  return (
    <Card className="flex gap-4 p-5">
      <SoftTile icon={icon} color={color} size={42} />
      <div className="min-w-0 flex-1">
        <h2 className="mb-2 text-[15px] font-semibold">{title}</h2>
        {children}
      </div>
    </Card>
  );
}

export default function Settings() {
  const { deleteMode, setDeleteMode } = useStore();
  const [fda, setFda] = useState<boolean | null>(null);
  const [dismissed, setDismissed] = useState(loadFdaDismissed);
  const [identity, setIdentity] = useState<AppIdentity | null>(null);

  // Only show the grant CTA when the check returns false. Re-check on focus so
  // returning from System Settings updates without another nag if already allowed.
  useEffect(() => {
    const check = () => {
      api
        .hasFullDiskAccess()
        .then((ok) => {
          setFda(ok);
          if (ok) {
            saveFdaDismissed(false);
            setDismissed(false);
          }
        })
        .catch(() => setFda(null));
    };
    check();
    api.appIdentity().then(setIdentity).catch(() => {});
    const onVis = () => {
      if (!document.hidden) check();
    };
    window.addEventListener("focus", check);
    document.addEventListener("visibilitychange", onVis);
    return () => {
      window.removeEventListener("focus", check);
      document.removeEventListener("visibilitychange", onVis);
    };
  }, []);

  const dismiss = () => {
    saveFdaDismissed(true);
    setDismissed(true);
  };
  const undismiss = () => {
    saveFdaDismissed(false);
    setDismissed(false);
  };

  const state = fdaUiState(fda, dismissed);

  const option = (mode: DeleteMode, title: string, text: string) => (
    <button
      onClick={() => setDeleteMode(mode)}
      aria-pressed={deleteMode === mode}
      className={cx(
        "flex flex-1 cursor-pointer items-start gap-3 rounded-[14px] border p-4 text-left transition",
        deleteMode === mode ? "border-accent/50 bg-accent-soft" : "glass hover:brightness-[1.02]",
      )}
    >
      <span className={cx("mt-0.5 flex size-4 shrink-0 items-center justify-center rounded-full border-2", deleteMode === mode ? "border-accent" : "border-faint/60")}>
        {deleteMode === mode && <span className="size-2 rounded-full bg-accent" />}
      </span>
      <span>
        <span className="block font-semibold">{title}</span>
        <span className="mt-1 block text-[12px] text-muted">{text}</span>
      </span>
    </button>
  );

  return (
    <Page title="Settings" subtitle="How Mr.Clean removes things, and what it can see.">
      <div className="flex flex-col gap-4">
        <Section icon={Trash2} color="var(--c-accent)" title="When cleaning">
          <div className="flex gap-3">
            {option("trash", `Move to ${words.trash} (recommended)`, `Undo-able: put things back from the ${words.trash}. Empty the ${words.trash} to actually free the space.`)}
            {option("permanent", "Delete permanently", "Frees space immediately. Can't be undone.")}
          </div>
        </Section>

        <BackgroundSection />

        {platform === "mac" && (
          <Section icon={HardDrive} color="var(--c-info)" title="Full Disk Access">
            {state === "granted" && (
              <p className="flex items-center gap-2 text-[13px] text-safe-text">
                <CircleCheck className="size-4" /> Granted. Mr.Clean can see every cache folder.
              </p>
            )}
            {state === "ask" && (
              <>
                <p className="text-[13px] text-muted">
                  macOS hides some folders (Trash, Mail, parts of ~/Library) until you allow it. Without it, scans still work but may miss some space. Open the setting, turn on
                  <b className="text-ink"> Mr.Clean</b>, then restart the app.
                </p>
                {identity && (
                  <p className="mt-2 break-all font-mono text-[11px] text-faint">
                    {identity.bundle_id}
                    <br />
                    {identity.path}
                  </p>
                )}
                <div className="mt-3 flex flex-wrap gap-2">
                  <Button onClick={() => openFullDiskAccessSettings()} disabled={!inTauri}>
                    Open Privacy settings
                  </Button>
                  <Button variant="ghost" onClick={dismiss}>
                    I&apos;ll do this later
                  </Button>
                </div>
              </>
            )}
            {state === "dismissed" && (
              <>
                <p className="text-[13px] text-muted">Not granted yet. Scans still work; some folders may be hidden.</p>
                <div className="mt-3 flex flex-wrap gap-2">
                  <Button onClick={() => openFullDiskAccessSettings()} disabled={!inTauri}>
                    Open Privacy settings
                  </Button>
                  <Button variant="ghost" onClick={undismiss}>
                    Show reminder
                  </Button>
                </div>
              </>
            )}
            {state === "loading" && <p className="text-[13px] text-muted">Checking…</p>}
          </Section>
        )}

        <Section icon={ShieldAlert} color="var(--c-danger)" title="Security scanner data">
          <ul className="list-disc space-y-1 pl-5 text-[13px] text-muted">
            <li>
              Quarantined items live in <code className="font-mono text-[11.5px]">~/.mrclean/quarantine</code> and can be restored from the Security page.
            </li>
            <li>
              To add newly published malicious package versions, place a JSON file at <code className="font-mono text-[11.5px]">~/.mrclean/iocs.json</code> using the same format as
              the bundled list. It's merged on the next scan.
            </li>
          </ul>
        </Section>

        <Section icon={Lock} color="var(--c-purple)" title="Privacy">
          <p className="text-[13px] text-muted">Nothing is ever uploaded. No accounts, no tracking, no automatic updates. All scanning happens on this {words.computer}.</p>
        </Section>
      </div>

      <p className="mt-5 text-[11.5px] text-faint">Mr.Clean 0.1.0</p>
    </Page>
  );
}

/** Menu bar / tray icon, automatic scans and their notifications. */
function BackgroundSection() {
  const { toast } = useStore();
  const [bg, setBg] = useState<BackgroundSettings | null>(null);

  useEffect(() => {
    api.backgroundSettings().then(setBg).catch(() => setBg(null));
  }, []);

  if (!bg) return null;
  const change = (patch: Partial<BackgroundSettings>) => {
    const next = { ...bg, ...patch };
    setBg(next);
    api.setBackgroundSettings(next).catch((e) => toast(String(e), "error"));
  };

  return (
    <Section icon={BellRing} color="var(--c-teal)" title={`${words.tray === "menu bar" ? "Menu bar" : "System tray"} & automatic scans`}>
      <div className="flex flex-col gap-4 text-[13px]">
        {bg.tray_available ? (
          <label className="flex cursor-pointer items-start gap-3">
            <span className="mt-0.5">
              <Checkbox checked={bg.keep_in_menu_bar} onChange={(v) => change({ keep_in_menu_bar: v })} label={`Keep Mr.Clean in the ${words.tray}`} />
            </span>
            <span>
              <span className="block font-medium">Keep Mr.Clean in the {words.tray} when the window is closed</span>
              <span className="block text-[12px] text-muted">
                See free disk, memory and security at a glance, and scan without opening the app. Quit from the {words.tray} icon.
              </span>
            </span>
          </label>
        ) : (
          <p className="text-[12px] text-muted">This desktop has no {words.tray}, so Mr.Clean closes with its window. Automatic scans run while it's open.</p>
        )}

        <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
          <span className="font-medium">Scan for security issues automatically</span>
          <Segmented<Schedule>
            label="Automatic scans"
            value={bg.auto_scan}
            onChange={(v) => change({ auto_scan: v })}
            options={[
              { value: "off", label: "Off" },
              { value: "daily", label: "Daily" },
              { value: "weekly", label: "Weekly" },
            ]}
          />
          {bg.auto_scan !== "off" && <span className="text-[12px] text-faint">Last automatic scan: {bg.last_auto_scan ? ago(bg.last_auto_scan) : "not yet"}</span>}
        </div>

        <div className={cx("flex flex-col gap-2", bg.auto_scan === "off" && "opacity-50")}>
          <span className="text-[12px] font-medium text-muted">Send a notification when</span>
          <label className="flex cursor-pointer items-center gap-3">
            <Checkbox checked={bg.notify_threats} disabled={bg.auto_scan === "off"} onChange={(v) => change({ notify_threats: v })} label="New security issues" />
            <span>A new security issue is found</span>
          </label>
          <label className="flex cursor-pointer items-center gap-3">
            <Checkbox checked={bg.notify_disk} disabled={bg.auto_scan === "off"} onChange={(v) => change({ notify_disk: v })} label="Disk almost full" />
            <span>Your disk is more than 90% full</span>
          </label>
        </div>
        <p className="text-[11.5px] text-faint">Automatic scans only read files, run on this {words.computer}, and never delete anything.</p>
      </div>
    </Section>
  );
}
