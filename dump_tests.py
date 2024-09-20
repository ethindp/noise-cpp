import json, os, sys, urllib.request as ur, itertools
from collections import defaultdict

if not os.path.exists("tests") or not os.path.exists("tests/vectors"):
    print(
        "Error: not running at the top-level repository root, or tests/vectors does not exist!"
    )
    sys.exit(1)

v1, v2 = json.loads(
    ur.urlopen(
        "https://raw.githubusercontent.com/centromere/cacophony/master/vectors/cacophony.txt"
    ).read()
), json.loads(
    ur.urlopen(
        "https://raw.githubusercontent.com/mcginty/snow/refs/heads/main/tests/vectors/snow.txt"
    ).read()
)
vectors = list(itertools.chain(v1["vectors"], v2["vectors"]))
protocol_counts = defaultdict(int)
test_names = []
for i, vector in enumerate(vectors):
    protocol = vector["protocol_name"]
    protocol_counts[protocol] += 1
    file_name = f"tests/vectors/{protocol}_{protocol_counts[protocol]}.json"
    test_names.append(f"{protocol}_{protocol_counts[protocol]}")
    if os.path.exists(f"tests/vectors/{file_name}"):
        print(f"Warning: overriding {file_name}")
    with open(file_name, "w") as f:
        f.write(json.dumps(vector, indent=4))

with open("tests/vectors/meson.build", "w") as f:
    f.write("tests = files(")
    for test_name in test_names:
        f.write(f"'{test_name}.json', ")
    f.write(""")

foreach tst: tests
""")
    f.write("test(fs.name(tst), test_runner, args: [tst])\n")
    f.write("endforeach\n")
