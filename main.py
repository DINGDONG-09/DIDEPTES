# Entry point CLI untuk menjalankan scanner
# Menangani argumen, memanggil Orchestrator, dan menulis report.

import argparse
from scanner.core import Orchestrator
from scanner.reporting import Reporter
from scanner.loading import SimpleLoader
from scanner.reporting_pdf import to_pdf
from datetime import datetime

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
    p.add_argument("--pdf", default=None, help="Path file PDF report (opsional, jika digunakan hanya export PDF saja)")
    p.add_argument("--auth-bruteforce", action="store_true", help="Enable authentication bruteforce test")


    return p.parse_args()

def main():
    print("🛡️  Mini-OWASP Web Scanner")
    print("=" * 40)
    
    args = parse_args()
    
    # Show target info
    print(f"🎯 Target: {args.target}")
    print(f"📊 Depth: {args.max_depth} | Rate: {args.rate} RPS")
    print()
    
    # Start scanning with loading animation - ONLY AT THE BEGINNING
    loader = SimpleLoader("🔍 Starting security scan")
    loader.start()
    
    try:
         # ✅ Add auth_options based on CLI args
        auth_options = {}
        if args.auth_bruteforce:
            auth_options["allow_bruteforce"] = True
        orch = Orchestrator(base_url=args.target,
                            max_depth=args.max_depth,
                            rate=args.rate,
                            scope=args.scope)
        
        # Stop the initial loader before running detailed checks
        loader.stop("Security scan initialized")
        
        # Now run the scan with individual check animations
        findings = orch.run()
        if findings is None:
            findings = []
            print("⚠️  Warning: Scanner returned no results")
        print(f"🎯 Scan completed - Found {len(findings)} total issues")
        
    except Exception as e:
        loader.stop(f"Scan failed: {str(e)}")
        return
    
        # Generate reports with loading
    report_loader = SimpleLoader("📝 Generating report")
    report_loader.start()

    try:
        if args.pdf:
            # PDF only mode
            to_pdf(findings, datetime.utcnow().isoformat() + "Z", args.pdf)
            report_loader.stop("PDF report generated successfully")
            print(f"📄 PDF: {args.pdf}")
        else:
            # default: JSON + HTML
            Reporter.to_json(findings, args.out)
            Reporter.to_html(findings, args.html)
            report_loader.stop("Reports generated successfully")
            print(f"📄 JSON: {args.out}")
            print(f"🌐 HTML: {args.html}")

        print("✅ All done!")
    except Exception as e:
        report_loader.stop(f"Report generation failed: {str(e)}")


if __name__ == "__main__":
    main()