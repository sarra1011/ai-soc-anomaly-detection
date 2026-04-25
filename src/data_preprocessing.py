import pandas as pd

def load_data(path):
    return pd.read_csv(path)

def preprocess(df):
    df['failed'] = df['status'].apply(lambda x: 1 if x == 'failed' else 0)
    return df
