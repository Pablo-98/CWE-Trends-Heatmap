import xml.etree.ElementTree as ET

# Load the XML file
tree = ET.parse('sample.xml')
root = tree.getroot()

# Print root tag
print("Root Tag:", root.tag)

# Iterate through books
for book in root.findall('book'):
    book_id = book.get('id')
    title = book.find('title').text
    author = book.find('author').text

    print(f"Book ID: {book_id}, Title: {title}, Author: {author}")