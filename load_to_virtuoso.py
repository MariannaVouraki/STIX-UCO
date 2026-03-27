from pathlib import Path
import requests

VIRTUOSO_SPARQL_ENDPOINT = "http://localhost:8890/sparql"
TTL_FILE = Path("out/ttl/all_examples.ttl")

def main():
    ttl_data = TTL_FILE.read_text(encoding="utf-8")

    sparql = f"""
    INSERT DATA {{
        GRAPH <http://example.org/graph/stix-uco> {{
{ttl_data}
        }}
    }}
    """

    response = requests.post(
        VIRTUOSO_SPARQL_ENDPOINT,
        data={"update": sparql},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        auth=("dba", "dba"),
        timeout=120,
    )

    print(response.status_code)
    print(response.text)

if __name__ == "__main__":
    main()