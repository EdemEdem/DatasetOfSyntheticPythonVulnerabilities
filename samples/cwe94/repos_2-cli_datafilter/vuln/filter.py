import argparse
import pandas as pd

def main():
    parser = argparse.ArgumentParser(description="Vulnerable CLI data filter tool")
    parser.add_argument("--csv", required=True, help="Input CSV file")
    parser.add_argument("--filter", required=True, help="Filter expression to apply")
    args = parser.parse_args()

    df = pd.read_csv(args.csv)

    # Apply filter using eval() directly => CWE-94 vulnerability
    for _, row in df.iterrows():
        # Build a namespace with column names as variables
        namespace = {col: row[col] for col in df.columns}
        try:
            if eval(args.filter, {}, namespace):
                print(','.join(str(namespace[col]) for col in df.columns))
        except Exception as e:
            print(f"Error evaluating filter: {e}")

if __name__ == "__main__":
    main()
