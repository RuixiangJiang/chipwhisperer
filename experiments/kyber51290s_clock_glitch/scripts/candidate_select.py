import pandas as pd
from pathlib import Path

csv_path = max(Path("../data/sweeps").glob("coarse_sweep_*/coarse_sweep.csv"),
               key=lambda p: p.stat().st_mtime)
print("Analyzing:", csv_path)

df = pd.read_csv(csv_path)

g = (
    df.groupby(["width", "offset", "repeat", "ext_offset", "classification"])
      .size()
      .unstack(fill_value=0)
      .reset_index()
)

for col in ["normal_correct", "normal_wrong_ss", "crash", "invalid_response", "timeout"]:
    if col not in g:
        g[col] = 0

g["total"] = g[["normal_correct", "normal_wrong_ss", "crash", "invalid_response", "timeout"]].sum(axis=1)
g["wrong_rate"] = g["normal_wrong_ss"] / g["total"]
g["crash_rate"] = g["crash"] / g["total"]
valid = g["normal_correct"] + g["normal_wrong_ss"]
g["valid_wrong_rate"] = g["normal_wrong_ss"] / valid.replace(0, pd.NA)

c = g[g["normal_wrong_ss"] > 0].copy()

print("\nTop candidates:")
print(
    c.sort_values(["normal_wrong_ss", "crash_rate", "valid_wrong_rate"],
                  ascending=[False, True, False])
     .head(30)
     [["width", "offset", "repeat", "ext_offset",
       "normal_correct", "normal_wrong_ss", "crash", "invalid_response",
       "wrong_rate", "crash_rate", "valid_wrong_rate"]]
     .to_string(index=False)
)

print("\nLow-crash candidates:")
print(
    c[c["crash_rate"] <= 0.2]
     .sort_values(["normal_wrong_ss", "wrong_rate"], ascending=[False, False])
     .head(30)
     [["width", "offset", "repeat", "ext_offset",
       "normal_correct", "normal_wrong_ss", "crash", "invalid_response",
       "wrong_rate", "crash_rate", "valid_wrong_rate"]]
     .to_string(index=False)
)