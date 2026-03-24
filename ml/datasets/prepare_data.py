import pandas as pd
import requests
import io
import os
from sklearn.model_selection import train_test_split

def fetch_urlhaus_phishing():
    print("Fetching URLhaus dataset...")
    url = "https://urlhaus.abuse.ch/downloads/csv_online/"
    try:
        df = pd.read_csv(url, comment='#', quotechar='"', skipinitialspace=True, on_bad_lines='skip')
        if 'url' in df.columns:
            phish = df[['url']].copy()
            phish['label'] = 1
            return phish
    except Exception as e:
        print(f"Failed to fetch URLhaus: {e}")
    return pd.DataFrame(columns=['url', 'label'])

def fetch_openphish():
    print("Fetching OpenPhish dataset...")
    url = "https://openphish.com/feed.txt"
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0'}
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        urls = [u.strip() for u in response.text.splitlines() if u.strip()]
        df = pd.DataFrame({'url': urls})
        df['label'] = 1
        return df
    except Exception as e:
        print(f"Failed to fetch OpenPhish: {e}")
    return pd.DataFrame(columns=['url', 'label'])

def fetch_benign_tranco():
    """
    Tranco list is the gold standard for benign domains — it's a research-grade
    ranking that merges Alexa, Majestic, Umbrella and Quantcast. Crucially we
    fetch the *full URL* with a realistic path so the benign examples structurally
    match phishing URLs (which always have paths). This is the main fix for the
    'google.com scores 33' bias — bare domains with no path made the model learn
    path-length as a phishing signal rather than URL semantics.
    """
    print("Fetching Tranco top-1M benign domains...")
    url = "https://tranco-list.eu/top-1m.csv.zip"
    try:
        import zipfile
        import io as _io
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0'}
        response = requests.get(url, headers=headers, timeout=60)
        response.raise_for_status()
        with zipfile.ZipFile(_io.BytesIO(response.content)) as z:
            with z.open('top-1m.csv') as f:
                df = pd.read_csv(f, header=None, names=['rank', 'domain'], nrows=50000)
        # Build realistic full URLs — include common paths so structure matches phishing data
        common_paths = [
            '', '/login', '/account', '/index.html', '/home',
            '/signin', '/dashboard', '/about', '/contact', '/search'
        ]
        import random
        random.seed(42)
        df['url'] = df['domain'].apply(
            lambda d: 'https://' + str(d).lower().strip() + random.choice(common_paths)
        )
        benign = df[['url']].copy()
        benign['label'] = 0
        print(f"  Got {len(benign)} Tranco benign URLs")
        return benign
    except Exception as e:
        print(f"Failed to fetch Tranco: {e}")
    return pd.DataFrame(columns=['url', 'label'])

def fetch_benign_majestic():
    print("Fetching Majestic Million benign dataset...")
    url = "http://downloads.majestic.com/majestic_million.csv"
    try:
        import random
        random.seed(99)
        df = pd.read_csv(url, nrows=50000)
        common_paths = [
            '', '/login', '/account', '/index.html', '/home',
            '/signin', '/dashboard', '/about', '/contact', '/search'
        ]
        df['url'] = df['Domain'].apply(
            lambda d: 'https://' + str(d).lower().strip() + random.choice(common_paths)
        )
        benign = df[['url']].copy()
        benign['label'] = 0
        print(f"  Got {len(benign)} Majestic benign URLs")
        return benign
    except Exception as e:
        print(f"Failed to fetch Majestic Million: {e}")
    return pd.DataFrame(columns=['url', 'label'])

def fetch_benign_cisa():
    """Kept as a smaller supplementary source."""
    print("Fetching CISA DotGov benign dataset...")
    url = "https://raw.githubusercontent.com/cisagov/dotgov-data/main/current-federal.csv"
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0'}
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        df = pd.read_csv(io.StringIO(response.text))
        domain_col = 'Domain Name' if 'Domain Name' in df.columns else df.columns[0]
        df['url'] = 'https://' + df[domain_col].astype(str).str.lower().str.strip()
        benign = df[['url']].copy()
        benign['label'] = 0
        print(f"  Got {len(benign)} CISA benign URLs")
        return benign
    except Exception as e:
        print(f"Failed to fetch CISA benign dataset: {e}")
    return pd.DataFrame(columns=['url', 'label'])


def clean_and_split(df):
    print(f"Total rows fetched: {len(df)}")
    if len(df) == 0:
        return pd.DataFrame(), pd.DataFrame(), pd.DataFrame()

    # Drop rows where url is not a string or is NaN
    df = df[df['url'].apply(lambda x: isinstance(x, str) and len(x) > 5)].copy()

    # Deduplicate
    df['url_lower'] = df['url'].str.lower().str.strip()
    df = df.drop_duplicates(subset=['url_lower']).drop(columns=['url_lower']).copy()
    print(f"Rows after deduplication: {len(df)}")

    phishing = df[df['label'] == 1]
    benign = df[df['label'] == 0]
    print(f"  Phishing: {len(phishing)}, Benign: {len(benign)}")

    min_count = min(len(phishing), len(benign))
    if min_count < 100:
        print(f"Error: Not enough data (Phishing: {len(phishing)}, Benign: {len(benign)})")
        return pd.DataFrame(), pd.DataFrame(), pd.DataFrame()

    phishing = phishing.sample(n=min_count, random_state=42)
    benign = benign.sample(n=min_count, random_state=42)

    balanced_df = pd.concat([phishing, benign]).sample(frac=1, random_state=42).reset_index(drop=True)
    print(f"Balanced dataset size: {len(balanced_df)} ({min_count} per class)")

    # Split 70/15/15
    train_df, temp_df = train_test_split(
        balanced_df, test_size=0.3, stratify=balanced_df['label'], random_state=42
    )
    val_df, test_df = train_test_split(
        temp_df, test_size=0.5, stratify=temp_df['label'], random_state=42
    )

    return train_df, val_df, test_df


def main():
    os.makedirs('data', exist_ok=True)

    phish1 = fetch_urlhaus_phishing()
    phish2 = fetch_openphish()
    benign1 = fetch_benign_tranco()   # PRIMARY benign source now
    benign2 = fetch_benign_majestic() # Secondary
    benign3 = fetch_benign_cisa()     # Supplementary

    all_data = pd.concat([phish1, phish2, benign1, benign2, benign3], ignore_index=True)

    train_df, val_df, test_df = clean_and_split(all_data)

    if len(train_df) > 0:
        print(f"Saving splits to data/ directory...")
        train_df.to_csv('data/train.csv', index=False)
        val_df.to_csv('data/val.csv', index=False)
        test_df.to_csv('data/test.csv', index=False)
        print("Done. Ready for real ML training.")
    else:
        print("Failed to prepare data: Not enough real records fetched.")


if __name__ == '__main__':
    main()