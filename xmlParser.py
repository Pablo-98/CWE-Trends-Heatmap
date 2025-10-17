import xml.etree.ElementTree as ET

tree = ET.parse('1200.xml')
root = tree.getroot()

print("Root Tag:", root.tag)

for 