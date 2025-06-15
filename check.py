import requests
import argparse
from rich import print
from rich.table import Table

RECOMMENDED_HEADERS = {
    "Content-Security-Policy": "Protects against XSS by controlling content sources.",
    "X-Frame-Options": "Prevents Clickjacking attacks.",
    "X-Content-Type-Options": "Prevents MIME-type sniffing.",
    "Referrer-Policy": "Controls how much referrer information is sent.",
    "Permissions-Policy": "Restricts access to browser APIs (camera, location, etc.).",
    "Strict-Transport-Security": "Enforces HTTPS connections.",
    "Cross-Origin-Embedder-Policy": "Protects embedded content from cross-origin abuse.",
    "Cross-Origin-Opener-Policy": "Isolates browsing context for security.",
    "Cross-Origin-Resource-Policy": "Protects resources from cross-origin abuse.",
}

def check_security_headers(url, specific_headers=None):
    print(f"[bold cyan]\n[+] Checking Security Headers for:[/] {url}\n")

    try:
        response = requests.get(url, timeout=10)
        headers = response.headers

        table = Table(title="Security Header Report", show_lines=True)
        table.add_column("Header", style="cyan", justify="left")
        table.add_column("Status", style="bold", justify="center")
        table.add_column("Description", justify="left")

        headers_to_check = (
            {h: RECOMMENDED_HEADERS.get(h, "No description available.") for h in specific_headers}
            if specific_headers else RECOMMENDED_HEADERS
        )

        for header, desc in headers_to_check.items():
            if header in headers:
                table.add_row(header, "[green]✓ Present[/]", desc)
            else:
                table.add_row(header, "[red]✗ Missing[/]", desc)

        print(table)

    except requests.exceptions.RequestException as e:
        print(f"[red]Error:[/] {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check HTTP Security Headers for a given URL.")
    parser.add_argument("url", help="Target URL (example: https://example.com)")
    parser.add_argument(
        "--headers",
        nargs="+",
        help="Specify headers to check (example: --headers X-Frame-Options Content-Security-Policy)",
    )

    args = parser.parse_args()
    check_security_headers(args.url, args.headers)

