def detect_anomalies(df):
    suspicious_users = df.groupby('user')['failed'].sum()
    return suspicious_users[suspicious_users > 2]
