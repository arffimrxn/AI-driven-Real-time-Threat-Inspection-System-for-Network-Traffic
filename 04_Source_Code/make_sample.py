import pandas as pd

# Replace this with your actual dataset file name
input_file = 'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv' 

# Read just the first 2,000 rows
df = pd.read_csv(input_file, nrows=2000)

# Save the sample into the required folder structure
df.to_csv('05_Data_or_Sample_Input/sample_ddos_traffic.csv', index=False)
print("Sample dataset created successfully in 05_Data_or_Sample_Input/!")