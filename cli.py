#!/usr/bin/env python3
"""
LTAT - command-line interface.

This is the original LTAT.py experience, kept working, but with ZERO analysis
logic of its own. Every score comes from the same modules the web app uses:

    app.analyzer.hybrid.analyze_url()  ->  heuristics + ML + threat intel

So a URL scanned here and the same URL scanned in the browser always produce an
identical verdict. The CLI is purely presentation.

New in 2.0: the report also prints the ML phishing probability and the hybrid
verdict, alongside the heuristic reasons the old tool already showed.

Usage
-----
    python cli.py https://example.com
    python cli.py https://example.com --json
    python cli.py --batch urls.txt -o report.json
    python cli.py https://example.com --no-cert --quiet
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from colorama import Fore, Style, init as colorama_init

from app.analyzer import hybrid, predictor
from app.config import APP_VERSION, THRESHOLD_MALICIOUS, THRESHOLD_SAFE

# colorama translates ANSI codes into Win32 console calls, which is what makes
# colour work in cmd.exe and PowerShell. autoreset avoids stray colour bleed.
colorama_init(autoreset=True)

RESET = Style.RESET_ALL
BOLD = Style.BRIGHT
DIM = Style.DIM
RED = Fore.RED
GREEN = Fore.GREEN
YELLOW = Fore.YELLOW
CYAN = Fore.CYAN
BLUE = Fore.BLUE
MAGENTA = Fore.MAGENTA

WIDTH = 70

VERDICT_COLOUR = {
    "Safe": GREEN,
    "Suspicious": YELLOW,
    "Malicious": RED,
}

SEVERITY_COLOUR = {
    "CRITICAL": RED,
    "HIGH": RED,
    "MEDIUM": YELLOW,
    "LOW": CYAN,
}

SEVERITY_ICON = {
    "CRITICAL": "!!",
    "HIGH": " *",
    "MEDIUM": " +",
    "LOW": " -",
}


def banner() -> None:
    print(f"""
{CYAN}{BOLD}+{'-' * (WIDTH - 2)}+
|{'LINK THREAT ANALYSIS TOOL'.center(WIDTH - 2)}|
|{'Heuristic Rules + Machine Learning'.center(WIDTH - 2)}|
+{'-' * (WIDTH - 2)}+{RESET}""")

    model_state = (f"{GREEN}ready ({predictor.model_name()}){RESET}"
                   if predictor.is_loaded()
                   else f"{YELLOW}not trained - run: python -m app.ml.train{RESET}")
    # The threat-intelligence lookup still runs and still feeds the score;
    # its status is simply not surfaced in the CLI output.
    print(f"  ML model   : {model_state}")
    print()


def section(title: str) -> None:
    print(f"\n{BLUE}{BOLD}{'-' * WIDTH}")
    print(f"  {title}")
    print(f"{'-' * WIDTH}{RESET}")


def risk_bar(score: float, width: int = 40) -> str:
    """A simple text meter, coloured by the band the score falls into."""
    filled = int(round(max(0.0, min(100.0, score)) / 100 * width))
    if score < THRESHOLD_SAFE:
        colour = GREEN
    elif score <= THRESHOLD_MALICIOUS:
        colour = YELLOW
    else:
        colour = RED
    return f"{colour}{'#' * filled}{DIM}{'.' * (width - filled)}{RESET}"


def print_report(result: dict, verbose: bool = False) -> None:
    """Full human-readable report for one URL."""
    verdict = result["verdict"]
    colour = VERDICT_COLOUR.get(verdict, CYAN)
    scores = result["scores"]

    section("TARGET")
    print(f"  URL      : {BOLD}{result['url']}{RESET}")
    print(f"  Hostname : {result['hostname'] or '(none)'}")
    ips = result.get("ip_addresses") or []
    print(f"  Resolved : {', '.join(ips[:3]) if ips else DIM + 'did not resolve' + RESET}")

    meta = result.get("metadata", {})
    print(f"  TLD      : {meta.get('tld') or '-'}    "
          f"Entropy: {meta.get('domain_entropy', '-')} bits    "
          f"Length: {meta.get('url_length', '-')} chars")

    # ---------------- score breakdown ----------------
    section("SCORE BREAKDOWN")
    print(f"  Heuristic rules    : {scores['heuristic']:>6.1f} / 100   "
          f"({len(result['reasons'])} rule(s) triggered)")

    if scores["ml_probability"] is None:
        print(f"  ML model           : {DIM}unavailable - {result.get('ml_message', '')}{RESET}")
    else:
        print(f"  ML phishing prob.  : {scores['ml_probability'] * 100:>6.1f} %     "
              f"({result.get('ml_model') or 'model'})")

    # The threat-intelligence sub-score and the raw fusion formula (which
    # names it) are deliberately not printed. Both stay in the JSON payload
    # and are still folded into the final score by hybrid.analyze_url().

    # ---------------- certificate ----------------
    cert = result.get("certificate", {})
    if cert.get("status") == "ok":
        section("TLS CERTIFICATE")
        print(f"  Issuer         : {cert.get('issuer_org') or cert.get('issuer_cn') or '-'}"
              f"{'  ' + YELLOW + '[free CA]' + RESET if cert.get('is_free_ca') else ''}")
        print(f"  Subject        : {cert.get('subject_cn') or '-'}")
        print(f"  Valid          : {cert.get('valid_from') or '?'}  ->  {cert.get('valid_to') or '?'}"
              f"   ({cert.get('days_to_expiry')} days left)")
        print(f"  Protocol       : {cert.get('tls_version') or '-'}   {cert.get('cipher') or ''}")

        def flag(label: str, value: bool, good_when: bool) -> str:
            good = (value == good_when)
            mark = "yes" if value else "no"
            return f"{label}: {(GREEN if good else RED)}{mark}{RESET}"

        print(f"  {flag('Chain trusted', bool(cert.get('chain_trusted')), True)}   "
              f"{flag('Hostname match', bool(cert.get('hostname_match')), True)}   "
              f"{flag('Self-signed', bool(cert.get('self_signed')), False)}")
        print(f"  SAN entries    : {cert.get('san_count', 0)}")
        fingerprint = cert.get("sha256_fingerprint", "")
        if fingerprint:
            print(f"  SHA-256        : {DIM}{fingerprint[:47]}...{RESET}")
    elif cert.get("status") != "skipped":
        section("TLS CERTIFICATE")
        print(f"  {DIM}No certificate retrieved ({cert.get('status')}): "
              f"{cert.get('error', '')}{RESET}")

    # ---------------- reasons ----------------
    if result["reasons"]:
        section("WHY THIS VERDICT")
        for reason in result["reasons"]:
            sev = reason["severity"]
            sev_colour = SEVERITY_COLOUR.get(sev, CYAN)
            icon = SEVERITY_ICON.get(sev, " -")
            print(f"  {sev_colour}{icon}{RESET} [{sev_colour}{sev:^8}{RESET}] "
                  f"{BOLD}+{reason['points']:<3}{RESET} {reason['message']}")
            if verbose:
                print(f"       {DIM}rule: {reason['rule']}{RESET}")
    else:
        section("WHY THIS VERDICT")
        print(f"  {GREEN}No heuristic rules triggered.{RESET}")

    # ---------------- final ----------------
    section("FINAL VERDICT")
    print(f"  {risk_bar(result['final_score'])}  {BOLD}{result['final_score']:.1f}{RESET}/100")
    print(f"\n  {colour}{BOLD}>> {verdict.upper()} <<{RESET}   "
          f"(confidence {result['confidence']}%)")

    advice = {
        "Safe": "No significant threats detected. Stay alert anyway.",
        "Suspicious": "Treat with caution. Verify the sender before entering anything.",
        "Malicious": "Do NOT enter credentials, OTPs or payment details. Report this link.",
    }
    print(f"  {DIM}{advice.get(verdict, '')}{RESET}\n")


def print_quiet(result: dict) -> None:
    """One line per URL - handy for batch runs."""
    colour = VERDICT_COLOUR.get(result["verdict"], CYAN)
    print(f"  {colour}{result['final_score']:>5.1f}{RESET}  "
          f"{colour}{result['verdict']:<11}{RESET} {result['url']}")


def scan(url: str, *, no_cert: bool, no_vt: bool) -> dict:
    """Run one URL through the shared engine."""
    return hybrid.analyze_url(url, check_cert=not no_cert, check_vt=not no_vt)


def write_output(results: list[dict], path: Path, fmt: str) -> None:
    """Export results as JSON or plain text (utf-8 always, for Windows)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if fmt == "json":
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(results, handle, indent=2, ensure_ascii=False, default=str)
    else:
        with open(path, "w", encoding="utf-8") as handle:
            for result in results:
                handle.write(f"URL     : {result['url']}\n")
                handle.write(f"Score   : {result['final_score']}/100\n")
                handle.write(f"Verdict : {result['verdict']} "
                             f"(confidence {result['confidence']}%)\n")
                handle.write(f"Reasons : {len(result['reasons'])}\n")
                for reason in result["reasons"]:
                    handle.write(f"   +{reason['points']:<3} [{reason['severity']}] "
                                 f"{reason['message']}\n")
                handle.write("-" * WIDTH + "\n")
    print(f"  {GREEN}Report written to {path}{RESET}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python cli.py",
        description=(
            "Link Threat Analysis Tool - hybrid phishing detection\n"
            "(heuristic rules + machine learning).\n\n"
            "Examples:\n"
            "  python cli.py https://example.com\n"
            "  python cli.py https://example.com --json\n"
            "  python cli.py --batch urls.txt -o report.json\n"
            "  python cli.py https://example.com --no-cert --quiet\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("url", nargs="?", help="the URL to analyse")
    parser.add_argument("-b", "--batch", metavar="FILE",
                        help="scan every URL in a text file (one per line, # for comments)")
    parser.add_argument("-o", "--output", metavar="FILE", help="write the results to a file")
    parser.add_argument("-f", "--format", choices=["json", "txt"], default="json",
                        help="format for --output (default: json)")
    parser.add_argument("-j", "--json", action="store_true",
                        help="print the full JSON result to stdout instead of a report")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="print one summary line per URL")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="also show the internal rule name for each reason")
    parser.add_argument("--no-cert", action="store_true",
                        help="skip the TLS certificate inspection (faster, fully offline)")
    parser.add_argument("--no-vt", action="store_true",
                        help="skip the online threat-intelligence lookup")
    parser.add_argument("--version", action="version", version=f"LTAT {APP_VERSION}")
    return parser


def main() -> int:
    args = build_parser().parse_args()

    if not args.url and not args.batch:
        build_parser().print_help()
        return 1

    results: list[dict] = []
    show_banner = not (args.quiet or args.json)

    if args.batch:
        batch_path = Path(args.batch)
        if not batch_path.is_file():
            print(f"{RED}Error: file not found - {batch_path}{RESET}", file=sys.stderr)
            return 1

        with open(batch_path, "r", encoding="utf-8") as handle:
            urls = [line.strip() for line in handle
                    if line.strip() and not line.strip().startswith("#")]

        if not urls:
            print(f"{YELLOW}No URLs found in {batch_path}.{RESET}", file=sys.stderr)
            return 1

        if show_banner:
            banner()
            print(f"  Batch scan: {len(urls)} URL(s) from '{batch_path}'\n")
            print(f"  {'Score':>5}  {'Verdict':<11} URL")
            print(f"  {'-' * 5}  {'-' * 11} {'-' * 40}")

        for url in urls:
            try:
                result = scan(url, no_cert=args.no_cert, no_vt=args.no_vt)
            except Exception as exc:
                print(f"  {RED}error{RESET}  {url}  ({exc})", file=sys.stderr)
                continue
            results.append(result)
            if not args.json:
                print_quiet(result)

        if show_banner:
            print(f"\n  {DIM}Batch complete - {len(results)} URL(s) scanned.{RESET}")

    else:
        if show_banner:
            banner()
        try:
            result = scan(args.url, no_cert=args.no_cert, no_vt=args.no_vt)
        except Exception as exc:
            print(f"{RED}Analysis failed: {exc}{RESET}", file=sys.stderr)
            return 1
        results.append(result)

        if args.json:
            print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
        elif args.quiet:
            print_quiet(result)
        else:
            print_report(result, verbose=args.verbose)

    if args.json and args.batch:
        print(json.dumps(results, indent=2, ensure_ascii=False, default=str))

    if args.output and results:
        write_output(results, Path(args.output), args.format)

    # Exit code 2 signals "something malicious was found" so the CLI can be
    # used inside a shell script or CI pipeline.
    return 2 if any(r["verdict"] == "Malicious" for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
