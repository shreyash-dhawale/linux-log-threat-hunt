import pandas as pd 

df = pd.read_csv('data/processed/parsed_event.csv')

print("\nTop failed source IPs:")
failed = df[df["event_type"] == "failed_password"]
print(failed["source_ip"].value_counts().head(10))

print("\nTop targeted usernames:")
print(failed["username"].value_counts().head(10))

print("Accepted logins from previously noisy IPs:")
accepted =df[df["event_type"] == "accepted_password"]
noisy_ips = set(failed["source_ip"].value_counts()[lambda x : x >= 3].index)
print(accepted[accepted["source_ip"].isin(noisy_ips)][["timestamp", "username", "source_ip"]].head(20))