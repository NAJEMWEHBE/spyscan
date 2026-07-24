# src/spyscan/cli.py
from __future__ import annotations
import argparse
from pathlib import Path
from spyscan import service
from spyscan.allowlist import Allowlist

def _collect_all(ctx):
    # Thin wrapper over the shared service collector so tests can still
    # monkeypatch cli._collect_all and have it flow through to the service.
    return service.collect_all(ctx)

def cmd_baseline(args):
    # Delegate to the reusable service; pass cli._collect_all so the test
    # monkeypatch of it is honored. Paths (root/db/indicators/allowlist) are
    # service's job now -- tests repoint them by monkeypatching service.ROOT.
    service.run_baseline(collect=_collect_all)

def cmd_scan(args):
    try:
        result = service.run_scan(collect=_collect_all,
                                  enable_defender=getattr(args, "defender", False))
    except RuntimeError:
        print("no baseline yet - run: spyscan baseline"); return 2

    findings = result["findings"]
    s = result["summary"]
    print(f"findings: {s['total']}  ALERT: {s['alert']}  "
          f"REVIEW: {s['review']}  allowlisted: {s['allowlisted']}")
    # Surface the actionable set (bucket owns 'which buckets we show'); findings
    # are already score-desc, so ALERT rows (>=8) precede REVIEW rows (4-7). The
    # bucket labels itself, so a new actionable bucket needs no change here.
    for f in findings:
        if f.is_actionable():
            print(f"  [{f.bucket} {f.score}] {f.fact.label} :: {', '.join(f.reasons)}")
    print(f"report: {result['report_html_path']}")
    return 0

def cmd_allowlist(args):
    """Print the active allowlist file path + per-rule counts so the user knows
    where to add their own known-good software."""
    path = service.allowlist_path()
    al = Allowlist.load(path)
    print(f"allowlist file: {path}")
    print(f"  exists: {path.exists()}")
    print(f"  path_globs:  {len(al.path_globs)}")
    print(f"  signers:     {len(al.signers)}")
    print(f"  sha256:      {len(al.sha256)}")
    print(f"  entity_keys: {len(al.entity_keys)}")
    for r in al.builtin_rules():
        print(f"  built-in:    {r}")
    print("Edit that file to allowlist your own software "
          "(known-bad signals always override it).")
    return 0

def cmd_canary(args):
    """Local honeyfile tripwire: plant decoys, check them, or remove them."""
    from spyscan import canary
    import time
    state = service.canary_state_path()

    if args.canary_cmd == "deploy":
        targets = [Path(args.into)] if args.into else None
        res = canary.deploy(targets=targets, state_path=state, now=time.time())
        print(f"planted {res['planted']} canary file(s); state: {res['state_path']}")
        for p in res["canaries"]:
            print(f"  decoy: {p}")
        if res["skipped"]:
            print(f"  ({len(res['skipped'])} location(s)/name(s) skipped - "
                  f"existing real file or unwritable)")
        if res["planted"] == 0:
            print("  WARNING: nothing was planted (all target names already exist?)")
        return 0

    if args.canary_cmd == "status":
        trips = canary.check(state, now=time.time())
        if not trips:
            print("no canaries deployed - run: spyscan canary deploy")
            return 0
        tripped = [t for t in trips if t["tripped"]]
        print(f"canaries: {len(trips)}  tripped: {len(tripped)}")
        for t in trips:
            mark = "TRIPPED" if t["tripped"] else "ok"
            print(f"  [{mark}] {t['path']}")
            if t["tripped"]:
                for r in t["reasons"]:
                    print(f"      - {r}")
        # non-zero exit signals a trip (like scan's ALERT) for scripting
        return 1 if tripped else 0

    if args.canary_cmd == "clear":
        res = canary.clear(state)
        print(f"removed {len(res['removed'])} canary file(s); state cleared")
        for p in res["removed"]:
            print(f"  removed: {p}")
        if res["missing"]:
            print(f"  ({len(res['missing'])} already gone)")
        return 0

    return 0


def cmd_app(args):
    """Launch the standalone desktop app (Flask server + native window)."""
    from spyscan.app.launch import main as launch_main
    return launch_main()

def main(argv=None):
    p = argparse.ArgumentParser(prog="spyscan")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("baseline").set_defaults(func=cmd_baseline)
    scan_p = sub.add_parser("scan")
    scan_p.add_argument("--defender", action="store_true",
                        help="also deep-scan the most suspicious files with Windows "
                             "Defender (MpCmdRun); slower, off by default")
    scan_p.set_defaults(func=cmd_scan)
    sub.add_parser("allowlist").set_defaults(func=cmd_allowlist)
    sub.add_parser("app").set_defaults(func=cmd_app)

    can = sub.add_parser("canary", help="local honeyfile tripwire")
    can.set_defaults(func=cmd_canary)
    can_sub = can.add_subparsers(dest="canary_cmd", required=True)
    can_deploy = can_sub.add_parser("deploy", help="plant decoy files")
    can_deploy.add_argument("--into", default=None,
                            help="plant only into this dir (default: "
                                 "Desktop + Documents + app canaries/)")
    can_sub.add_parser("status", help="list canaries + whether any tripped")
    can_sub.add_parser("clear", help="remove decoy files + state")

    args = p.parse_args(argv)
    return args.func(args) or 0

if __name__ == "__main__":
    raise SystemExit(main())
