import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt

# Import functions from your parser file
from fileProcessor import parse_cwe_xml, is_software_cwe, is_hardware_cwe

# Define the list of files and their labels (years) 
files_and_labels = [
    ("2019.xml", "2019"),
    ("2020.xml", "2020"),
    ("2021.xml", "2021"),
    ("2022.xml", "2022"),
    ("2023.xml", "2023")
]


#  Parse XML files + extract rank information from order
parsed = {}
rankings = {}   # NEW — track rank per year
sets = {}

for file_path, label in files_and_labels:
    data = parse_cwe_xml(file_path)  # CWE → {name, score}
    parsed[label] = data

    # rank = index in the order they appear (1-based)
    rankings[label] = {cwe_id: rank for rank, cwe_id in enumerate(data.keys(), start=1)}

    # classify software/hardware
    software = {cwe for cwe in data.keys() if is_software_cwe(cwe)}
    hardware = {cwe for cwe in data.keys() if is_hardware_cwe(cwe)}

    sets[label] = {
        "software": software,
        "hardware": hardware
    }

labels = [lbl for _, lbl in files_and_labels]


#  SOFTWARE RANK HEATMAP 

software_union = sorted(set.union(*[sets[lbl]["software"] for lbl in labels]))

# build rank matrix (0 = absent, or large value for missing)
software_rank_matrix = []
for cwe in software_union:
    row = []
    for label in labels:
        row.append(rankings[label].get(cwe, 0))  # 0 = absent
    software_rank_matrix.append(row)

df_rank_sw = pd.DataFrame(software_rank_matrix, index=software_union, columns=labels)

# Plot software rank heatmap
plt.figure(figsize=(10, 8))
sns.heatmap(df_rank_sw, cmap="YlGnBu", cbar=True, annot=False)
plt.title("Software CWE Rank Heatmap (Darker = Higher Priority in Top 25)")
plt.xlabel("Year")
plt.ylabel("CWE ID")
plt.savefig("software_rank_heatmap.png", dpi=300, bbox_inches='tight')
plt.show()


#  HARDWARE PRESENCE HEATMAP (restored)

hardware_union = sorted(set.union(*[sets[lbl]["hardware"] for lbl in labels]))
hardware_matrix = [
    [1 if cwe in sets[label]["hardware"] else 0 for label in labels]
    for cwe in hardware_union
]
df_hw = pd.DataFrame(hardware_matrix, index=hardware_union, columns=labels)

plt.figure(figsize=(10, 8))
sns.heatmap(df_hw, cmap="Reds", cbar=True, annot=False)
plt.title("Hardware CWE Presence Heatmap (1 = Present in Top 25)")
plt.xlabel("Year")
plt.ylabel("CWE ID")
plt.savefig("hardware_presence_heatmap.png", dpi=300, bbox_inches='tight')
plt.show()
