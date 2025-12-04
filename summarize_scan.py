# summarize_scan.py


#usage :

# python summarize_scan.py scan_results.json

import sys, json

def summarize(path):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    pages = len(data)
    total_forms = sum(len(e.get("forms",[])) for e in data)
    total_inputs = sum(len(inp.get("inputs",[])) for e in data for inp in e.get("forms",[]))
    pages_no_forms = sum(1 for e in data if not e.get("forms"))
    print(f"Pages scanned: {pages}")
    print(f"Pages with no forms: {pages_no_forms}")
    print(f"Total forms found: {total_forms}")
    print(f"Total input fields found: {total_inputs}")
    print("\nTop 10 pages (first listed):")
    for i,e in enumerate(data[:10],1):
        print(f"{i}. {e.get('page')}  (forms: {len(e.get('forms',[]))}, links: {len(e.get('links',[]))})")
if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python summarize_scan.py <scan_results.json>")
    else:
        summarize(sys.argv[1])
