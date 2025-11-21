import xml.etree.ElementTree as ET

# -------------------------------------
#  AUTO-DETECT NAMESPACE + PARSE XML
# -------------------------------------
def parse_cwe_xml(file_path):
    tree = ET.parse(file_path)
    root = tree.getroot()

    # Auto-detect namespace
    if root.tag.startswith("{"):
        ns_uri = root.tag.split("}")[0].strip("{")
        ns = {"cwe": ns_uri}
    else:
        ns = {}

    data = {}

    # Enumerate Weakness elements to extract rank by order
    for rank, w in enumerate(root.findall(".//cwe:Weakness", ns), start=1):
        cwe_id = w.get("ID")
        name = w.get("Name")

        # Score may or may not exist
        score_tag = w.find("cwe:Score", ns)
        score = float(score_tag.text) if score_tag is not None else None

        if cwe_id:
            data[cwe_id] = {
                "name": name,
                "score": score,
                "rank": rank  # rank based on position in XML
            }

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
