import json, sys

try:
    with open("response.json", "r") as f:
        data = json.load(f)
        seed = data.get("encrypted_seed", "")
        print(seed)
except Exception as e:
    print("ERROR:", e, file=sys.stderr)
    sys.exit(1)
