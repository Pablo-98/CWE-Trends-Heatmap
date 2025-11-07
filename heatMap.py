import seaborn as sns
import matplotlib.pyplot as plt
import pandas as pd

df = pd.DataFrame(presence_matrix, index=all_cwes, columns=labels)

plt.figure(figsize=(12, 8))
sns.heatmap(df, cmap="Blues", annot=True, cbar=True)
plt.title("CWE Presence Heatmap (Top 25 Over Years)")
plt.show()