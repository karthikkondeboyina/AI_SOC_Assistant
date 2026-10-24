
from pathlib import Path
import pandas as pd

data_dir = Path("data/raw")
files = sorted(data_dir.glob("*.parquet"))

if not files:
    print("No Parquet files found in data/raw.")
    print("Please copy the downloaded files into that folder.")
else:
    print(f"Found {len(files)} Parquet files.\n")

    for file in files:
        print("=" * 65)
        print("FILE:", file.name)

        try:
            df = pd.read_parquet(file)

            print("Rows:", len(df))
            print("Columns:", len(df.columns))
            print("Column names:")
            print(df.columns.tolist())
            print("\nFirst 3 rows:")
            print(df.head(3).to_string(index=False))

        except Exception as exc:
            print("Could not read this file:", exc)
