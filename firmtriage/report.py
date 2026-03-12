'''
report.py

Purpose:
	•	Convert structured findings into printable format

Later:
	•	JSON
	•	Markdown

For now:
	•	Just return string
'''

def generate_report(results):
    print("\n==== Firmware Triage Report =====")
    print("Metadata:")
    for k, v in results["metadata"].items():
        print(f"	{k}: {v}")
    print("\nEntropy:")
    print(results["entropy"])
    print("\nStrings summary:")
    strings = results["strings"]
    print(f"	total strings: {strings['count_total']}")
    print("\n	sample strings:")
    for s in strings["top_samples"][:10]:
        print(f"	- {s}")
    print("\n	urls:", strings["urls"])
    print("		ips:", strings["ips"])
    print("\nMagic detection:")
    magic = results["magic"]

    if magic["count_total"] == 0:
        print("     no known signatures detected")
    else:
        for match in magic["matches"]:
            print(f"        - {match}")