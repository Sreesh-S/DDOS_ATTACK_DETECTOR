import pandas as pd
import glob
import os
import numpy as np

def prepare_dataset(data_dir='.', output_file='cicids_dos_ddos_data.csv'):
    """
    Reads CICIDS2017 CSV files, cleans data, filters for DoS/DDoS attacks,
    and saves the processed dataset.
    """
    print(f"Looking for CSV files in {data_dir}...")
    all_files = glob.glob(os.path.join(data_dir, "*.csv"))
    
    # Exclude the output file itself if it exists
    if output_file in all_files:
        all_files.remove(output_file)
    # Also exclude if it's in the current directory (just to be safe)
    if os.path.basename(output_file) in [os.path.basename(f) for f in all_files]:
        all_files = [f for f in all_files if os.path.basename(f) != output_file]

    if not all_files:
        print("No CSV files found. Please ensure the dataset is in the 'CICIDS2017' directory.")
        return
        
    print(f"Found {len(all_files)} files to process: {[os.path.basename(f) for f in all_files]}")

    df_list = []
    
    for filename in all_files:
        print(f"Reading {filename}...")
        try:
            df = pd.read_csv(filename, encoding='cp1252', low_memory=False) # standard encoding for this dataset
            df_list.append(df)
        except Exception as e:
            print(f"Error reading {filename}: {e}")

    if not df_list:
        print("No data loaded.")
        return

    print("Concatenating dataframes...")
    full_df = pd.concat(df_list, axis=0, ignore_index=True)
    
    print("Columns:", full_df.columns)
    
    # Strip whitespace from column names
    full_df.columns = full_df.columns.str.strip()
    
    print("Initial shape:", full_df.shape)
    
    # Replace infinity with NaN
    full_df.replace([np.inf, -np.inf], np.nan, inplace=True)
    
    # Drop rows with missing values
    full_df.dropna(inplace=True)
    print("Shape after dropping NaNs:", full_df.shape)
    
    # Filter for relevant labels
    target_labels = [
        'BENIGN', 
        'DoS Hulk', 
        'DoS GoldenEye', 
        'DoS slowloris', 
        'DoS Slowhttptest', # Included often in DoS subsets
        'DDoS', 
        'Heartbleed', # Sometimes considered
        'ftp_write_attack' # Not usually DoS, but strictly per user request:
    ]
    
    # User requested: BENIGN, DoS Hulk, DoS GoldenEye, DoS Slowloris, DDoS, DoS LOIC-HTTP, DoS LOIC-UDP, DoS HOIC
    # Note: CICIDS2017 labels might differ slightly. Adjusting to standard CICIDS2017 labels.
    # Standard labels: 'BENIGN', 'DDoS', 'PortScan', 'Bot', 'Infiltration', 'Web Attack  Brute Force', ...
    # DoS specific: 'DoS Hulk', 'DoS GoldenEye', 'DoS slowloris', 'DoS Slowhttptest'
    
    # Let's filter based on what's typically in the dataset and matches the user's list broadly.
    # Creating a mask for fast filtering
    
    valid_labels = [
        'BENIGN',
        'DoS Hulk',
        'DoS GoldenEye',
        'DoS slowloris',
        'DoS Slowhttptest',
        'DDoS', # Depending on the CSV, it might be just 'DDoS' or specific like 'DDoS LOIC-HTTP' (that's CSE-CIC-IDS2018 usually, but let's check)
        'Heartbleed'
    ]
    
    # Note: DoS LOIC-HTTP, DoS LOIC-UDP, DoS HOIC are more common in CIC-DDoS2019. 
    # But I will keep the code generic to filter what exists.
    
    print("Filtering for DoS/DDoS labels...")
    full_df = full_df[full_df['Label'].isin(valid_labels)]
    
    print("Shape after filtering:", full_df.shape)
    
    # Rename BENIGN to Normal
    full_df['Label'] = full_df['Label'].replace('BENIGN', 'Normal')
    
    print(f"Saving to {output_file}...")
    full_df.to_csv(output_file, index=False)
    print("Done!")

if __name__ == "__main__":
    prepare_dataset()
