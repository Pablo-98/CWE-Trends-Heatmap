import xml.etree.ElementTree as ET

import xml.etree.ElementTree as ET

def parse_cwe_xml(file_path):
    tree = ET.parse(file_path)
    root = tree.getroot()

    data = {}

    for weakness in root.iter("Entry"):
        # Get CWE ID
        id_tag = weakness.find("ID")
        if id_tag is not None:
            cwe_id = id_tag.text
        else:
            cwe_id = None

        # Get CWE Name
        name_tag = weakness.find("Name")
        if name_tag is not None:
            name = name_tag.text
        else:
            name = None

        # Get CWE Score
        score = None
        score_tag = weakness.find("Score")
        if score_tag is not None:
            score = float(score_tag.text)

        # Only store if we have a valid ID
        if cwe_id:
            #cwe_id is the key, and the value is a dictionary with name and score
            data[cwe_id] = {
                "name": name,
                "score": score
            }

    return data



def compare_years(file1, file2, label1="Year 1", label2="Year 2"):
    y1 = parse_cwe_xml(file1)
    y2 = parse_cwe_xml(file2)

    # set function creates a set object, which is an unordered collection of unique elements.
    #y1.keys() returns a view object that displays a list of all the keys in the dictionary y1.
    set1 = set(y1.keys())
    set2 = set(y2.keys())

#comparing two lists with set operations
    common = set1 & set2
    removed = set1 - set2
    added = set2 - set1

    print(f"\n-------CWE Trend Analysis for {label1} and {label2} -------")
#sorted function creates a new sorted list from the items in an iterable.
    print("\n Present in both years:")
    for cwe in sorted(common):
        print(f"{cwe} - {y1[cwe]['name']}")

    print("\n Removed from list:")
    for cwe in sorted(removed):
        print(f"{cwe} - {y1[cwe]['name']}")

    print("\n  Newly added to list:")
    for cwe in sorted(added):
        print(f"{cwe} - {y2[cwe]['name']}")




if __name__ == "__main__":
    compare_years("top24.xml", "top25.xml", "2025", "2024")
