import xml.etree.ElementTree as ET

# Load XML and register namespace to simplify tag access
tree = ET.parse('1200.xml')
root = tree.getroot()

# Namespace used in the file
ns = {'cwe': 'http://cwe.mitre.org/cwe-7'}

# Iterate through each Weakness in the file
for weakness in root.findall('.//cwe:Weakness', ns):
    cwe_id = weakness.get('ID')
    name = weakness.get('Name')

    # Get description (first text block)
    description_tag = weakness.find('cwe:Description', ns)
    description = description_tag.text.strip() if description_tag is not None else "N/A"

    print(f"CWE-{cwe_id}: {name}")
    print(f"  Description: {description}")

    # Pull common consequences (optional)
    consequences = weakness.findall('.//cwe:Consequence', ns)
    for consequence in consequences:
        scopes = [s.text for s in consequence.findall('cwe:Scope', ns)]
        impacts = [i.text for i in consequence.findall('cwe:Impact', ns)]
        print(f"    Consequence: Scope={scopes}, Impact={impacts}")

    print("-" * 50)