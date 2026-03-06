'''
Purpose:
- Parse command line arguments
- call scanner
- print results

'''
import argparse
from firmtriage.scanner import FirmwareScanner
from firmtriage.report import generate_report

def main():
    parser = argparse.ArgumentParser(description="Firmware triage tool")

    parser.add_argument(
        "file",
        help="Firmware file to anaylze"
    )

    args = parser.parse_args()

    scanner = FirmwareScanner(args.file)
    results = scanner.scan()

    generate_report(results)

if __name__ == "__main__":
    main()