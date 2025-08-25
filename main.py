 # Entry point CLI untuk menjalankan scanner
# Menangani argumen, memanggil Orchestrator, dan menulis report.

import argparse
from scanner.core import Orchestrator
from scanner.reporting import Reporter

def parse_args():
    # Definisi opsi CLI
    p = argparse.ArgumentParser(description="Mini-OWASP Web Scanner")
    p.add_argument("--target", required=True, help="Base URL target (contoh: https://example.com)")
    p.add_argument("--max-depth", type=int, default=1, help="Kedalaman crawl (default 1)")
    p.add_argument("--rate", type=float, default=2.0, help="Rate limit RPS (default 2)")
    p.add_argument("--out", default="report.json", help="Path file JSON report")
    p.add_argument("--html", default="report.html", help="Path file HTML report")
    p.add_argument("--scope", choices=["same-domain", "same-host"], default="same-domain",
                   help="Batasan scope crawling")
    return p.parse_args()

def main():
    args = parse_args()
    orch = Orchestrator(base_url=args.target,
                        max_depth=args.max_depth,
                        rate=args.rate,
                        scope=args.scope)
    findings = orch.run()                   # jalankan seluruh checks
    Reporter.to_json(findings, args.out)    # simpan JSON
    Reporter.to_html(findings, args.html)   # simpan HTML
    print(f"[OK] Report ditulis ke {args.out} & {args.html}")

if __name__ == "__main__":
    main()

