import xml.etree.ElementTree as ET


def parse_cwe_xml(file_path):
    tree = ET.parse(file_path)
    root = tree.getroot()

    ns = {"cwe": "http://cwe.mitre.org/cwe-7"}  # namespace dictionary

    data = {}

    # Find all Weakness elements using namespace
    for w in root.findall(".//cwe:Weakness", ns):

        cwe_id = w.get("ID")
        name = w.get("Name")

        # Score may not exist in this format
        score_tag = w.find("cwe:Score", ns)
        score = float(score_tag.text) if score_tag is not None else None

        if cwe_id:
            data[cwe_id] = {"name": name, "score": score}

    return data


def compare_multiple_years(files_and_labels):
    parsed = {}
    sets = {}

    for file_path, label in files_and_labels:
        data = parse_cwe_xml(file_path)
        parsed[label] = data
        sets[label] = set(data.keys())

    labels = [lbl for _, lbl in files_and_labels]

    # Present in ALL
    common = set.intersection(*sets.values())

    # Present in ANY
    all_cwes = set.union(*sets.values())

    # Unique per year
    unique = {}
    for lbl in labels:
        unique[lbl] = sets[lbl] - (all_cwes - sets[lbl])

    # Year-to-year changes
    diffs = {}
    for i in range(len(labels) - 1):
        prev = labels[i]
        next_ = labels[i+1]
        diffs[(prev, next_)] = {
            "added": sets[next_] - sets[prev],
            "removed": sets[prev] - sets[next_]
        }


    print("\n======== CWE TREND ANALYSIS ========\n")

    print(" Present in ALL years:")
    for cwe in sorted(common):
        print(f"{cwe} - {parsed[labels[0]][cwe]['name']}")

    print("\n Unique to each year:")
    for lbl in labels:
        print(f"\n  YEAR {lbl}:")
        for cwe in sorted(unique[lbl]):
            print(f"    {cwe} - {parsed[lbl][cwe]['name']}")

    print("\n Year-to-year changes:")
    for (prev, next_), result in diffs.items():
        print(f"\n  {prev} ➜ {next_}")
        
        print("    Added:")
        for cwe in sorted(result["added"]):
            print(f"      {cwe} - {parsed[next_][cwe]['name']}")

        print("    Removed:")
        for cwe in sorted(result["removed"]):
            print(f"      {cwe} - {parsed[prev][cwe]['name']}")





if __name__ == "__main__":
    compare_multiple_years([("2019.xml", "2019") , ("2020.xml", "2020"),("2021.xml", "2021"),("2022.xml", "2022"),("2023.xml", "2023")])
