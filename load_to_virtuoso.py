from pathlib import Path
import requests

VIRTUOSO_SPARQL_ENDPOINT = "http://localhost:8890/sparql"
TTL_FILE = Path("02_Output/ttl/all_examples.ttl")

def main():
    if not TTL_FILE.exists():
        print(f"File not found: {TTL_FILE.resolve()}")
        return

    ttl_data = TTL_FILE.read_text(encoding="utf-8")
    print(f"Loaded file: {TTL_FILE.resolve()}")
    print(f"Size: {len(ttl_data)} characters")

if __name__ == "__main__":
    main()