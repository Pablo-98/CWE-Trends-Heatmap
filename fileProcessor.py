import xml.etree.ElementTree as ET


# -------------------------------
#  AUTO-DETECT NAMESPACE + PARSE
# -------------------------------
def parse_cwe_xml(file_path):
    tree = ET.parse(file_path)
    root = tree.getroot()

    # Auto-detect namespace from XML
    if root.tag.startswith("{"):
        ns_uri = root.tag.split("}")[0].strip("{")
        ns = {"cwe": ns_uri}
    else:
        ns = {}

    data = {}

    # Find all <Weakness> elements
    for w in root.findall(".//cwe:Weakness", ns):
        cwe_id = w.get("ID")
        name = w.get("Name")

        # Score may exist or not
        score_tag = w.find("cwe:Score", ns)
        score = float(score_tag.text) if score_tag is not None else None

        if cwe_id:
            data[cwe_id] = {"name": name, "score": score}

    return data



def is_software_cwe(cwe_id):
    try:
        return int(cwe_id) < 1000
    except:
        return False


def is_hardware_cwe(cwe_id):
    try:
        return int(cwe_id) >= 1000
    except:
        return False


# -------------------------------
#  MAIN MULTI-YEAR ANALYSIS
# -------------------------------
def compare_multiple_years(files_and_labels):
    parsed = {}
    sets = {}

    # Parse each XML file
    for file_path, label in files_and_labels:
        data = parse_cwe_xml(file_path)
        parsed[label] = data

        software = {cwe for cwe in data.keys() if is_software_cwe(cwe)}
        hardware = {cwe for cwe in data.keys() if is_hardware_cwe(cwe)}

        sets[label] = {
            "software": software,
            "hardware": hardware
        }

    labels = [lbl for _, lbl in files_and_labels]

    print("\n======== CWE TREND ANALYSIS ========\n")


    # ======================================================
    #                SOFTWARE CWE ANALYSIS
    # ======================================================
    print("\n================ SOFTWARE CWE TRENDS (ID < 1000) ================\n")

    software_sets = [sets[lbl]["software"] for lbl in labels]

    # Present in ALL software years
    if all(len(s) > 0 for s in software_sets):
        software_common = set.intersection(*software_sets)
    else:
        software_common = set()

    print(" Present in ALL software years:")
    for cwe in sorted(software_common):
        print(f"  {cwe} - {parsed[labels[0]][cwe]['name']}")



    # TRUE UNIQUE SOFTWARE CWEs PER YEAR
    print("\n Unique software CWE per year (true uniques):")

    # Build union of all software years
    sw_union = set.union(*software_sets)

    for lbl in labels:
        other_years = [sets[o]["software"] for o in labels if o != lbl]

        if other_years:
            others_union = set.union(*other_years)
        else:
            others_union = set()

        unique_sw = sets[lbl]["software"] - others_union

        if unique_sw:
            print(f"\n  YEAR {lbl}:")
            for cwe in sorted(unique_sw):
                print(f"    {cwe} - {parsed[lbl][cwe]['name']}")


    # YEAR-TO-YEAR SOFTWARE CHANGES
    print("\n Software YEAR-TO-YEAR CHANGES:\n")

    for i in range(len(labels) - 1):
        prev = labels[i]
        nxt = labels[i + 1]

        prev_set = sets[prev]["software"]
        next_set = sets[nxt]["software"]

        added = next_set - prev_set
        removed = prev_set - next_set

        print(f"  {prev} ➜ {nxt}")

        print("    Added:")
        for cwe in sorted(added):
            print(f"      {cwe} - {parsed[nxt][cwe]['name']}")

        print("    Removed:")
        for cwe in sorted(removed):
            print(f"      {cwe} - {parsed[prev][cwe]['name']}")

        print()



    # ======================================================
    #                HARDWARE CWE ANALYSIS
    # ======================================================
    print("\n================ HARDWARE CWE TRENDS (ID ≥ 1000) ================\n")

    hardware_sets = [sets[lbl]["hardware"] for lbl in labels]

    # Present in ALL hardware years
    if all(len(s) > 0 for s in hardware_sets):
        hardware_common = set.intersection(*hardware_sets)
    else:
        hardware_common = set()

    print(" Present in ALL hardware years:")
    for cwe in sorted(hardware_common):
        print(f"  {cwe} - {parsed[labels[0]][cwe]['name']}")


    # TRUE UNIQUE HARDWARE CWEs PER YEAR
    print("\n Unique hardware CWE per year (true uniques):")

    hw_union = set.union(*hardware_sets)

    for lbl in labels:
        other_years = [sets[o]["hardware"] for o in labels if o != lbl]

        if other_years:
            others_union = set.union(*other_years)
        else:
            others_union = set()

        unique_hw = sets[lbl]["hardware"] - others_union

        if unique_hw:
            print(f"\n  YEAR {lbl}:")
            for cwe in sorted(unique_hw):
                print(f"    {cwe} - {parsed[lbl][cwe]['name']}")


    # YEAR-TO-YEAR HARDWARE CHANGES
    print("\n Hardware YEAR-TO-YEAR CHANGES:\n")

    for i in range(len(labels) - 1):
        prev = labels[i]
        nxt = labels[i + 1]

        prev_set = sets[prev]["hardware"]
        next_set = sets[nxt]["hardware"]

        added = next_set - prev_set
        removed = prev_set - next_set

        print(f"  {prev} ➜ {nxt}")

        print("    Added:")
        for cwe in sorted(added):
            print(f"      {cwe} - {parsed[nxt][cwe]['name']}")

        print("    Removed:")
        for cwe in sorted(removed):
            print(f"      {cwe} - {parsed[prev][cwe]['name']}")

        print()



if __name__ == "__main__":
    compare_multiple_years([
        ("2019.xml", "2019"),
        ("2020.xml", "2020"),
        ("2021.xml", "2021"),
        ("2022.xml", "2022"),
        ("2023.xml", "2023")
    ])
