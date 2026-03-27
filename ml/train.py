import os
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(os.path.dirname(__file__)), '.env'))

import logging
import torch
import numpy as np
from torch.utils.data import Dataset, DataLoader
import torch.nn as nn
from transformers import DistilBertTokenizerFast, DistilBertForSequenceClassification
from sklearn.metrics import accuracy_score, precision_recall_fscore_support
import pandas as pd
import mlflow
from tqdm import tqdm

logging.getLogger("transformers.modeling_utils").setLevel(logging.ERROR)
logging.getLogger("transformers.configuration_utils").setLevel(logging.ERROR)
logging.getLogger("accelerate").setLevel(logging.ERROR)
os.environ["TOKENIZERS_PARALLELISM"] = "false"

# --- Configuration ---
MODEL_NAME = 'distilbert-base-uncased'
MAX_LEN = 128
BATCH_SIZE = 32
EPOCHS = 5          # ✅ Increased from 3 — DistilBERT needs more epochs to converge on URL data
LEARNING_RATE = 2e-5
DEVICE = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
MODEL_SAVE_DIR = 'ml/models/distilbert-phish'

# --- Dataset Definition ---
class PhishingDataset(Dataset):
    def __init__(self, csv_file, tokenizer, max_len):
        self.df = pd.read_csv(csv_file) if os.path.exists(csv_file) else None
        self.tokenizer = tokenizer
        self.max_len = max_len

    def __len__(self):
        return len(self.df) if self.df is not None else 0

    def __getitem__(self, idx):
        if self.df is None:
            return None

        url = str(self.df.iloc[idx]['url'])
        label = int(self.df.iloc[idx]['label'])

        encoding = self.tokenizer(
            url,
            add_special_tokens=True,
            max_length=self.max_len,
            return_token_type_ids=False,
            padding='max_length',
            truncation=True,
            return_attention_mask=True,
            return_tensors='pt',
        )

        return {
            'input_ids': encoding['input_ids'].flatten(),
            'attention_mask': encoding['attention_mask'].flatten(),
            'labels': torch.tensor(label, dtype=torch.float)
        }

def get_data_loader(csv_file, tokenizer, max_len, batch_size):
    """
    ✅ Removed WeightedRandomSampler — prepare_data.py already balances the
    dataset 1:1, so applying a sampler on top was redundant and wasted compute.
    shuffle=True is sufficient.
    """
    dataset = PhishingDataset(csv_file, tokenizer, max_len)
    if len(dataset) == 0:
        return None
    return DataLoader(dataset, batch_size=batch_size, shuffle=True)

# --- Training Loop ---
def train_epoch(model, data_loader, optimizer, device, epoch):
    model = model.train()
    losses = []
    loss_fn = nn.BCEWithLogitsLoss()
    progress_bar = tqdm(data_loader, desc=f'Epoch {epoch}')

    for batch in progress_bar:
        input_ids = batch['input_ids'].to(device)
        attention_mask = batch['attention_mask'].to(device)
        labels = batch['labels'].to(device).unsqueeze(1)

        optimizer.zero_grad()
        outputs = model(input_ids=input_ids, attention_mask=attention_mask)
        loss = loss_fn(outputs.logits, labels)
        losses.append(loss.item())
        loss.backward()
        nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
        optimizer.step()
        progress_bar.set_postfix({'loss': loss.item()})

    return sum(losses) / len(losses)

def eval_model(model, data_loader, device):
    model = model.eval()
    losses = []
    preds = []
    true_labels = []
    loss_fn = nn.BCEWithLogitsLoss()

    with torch.no_grad():
        for batch in data_loader:
            input_ids = batch['input_ids'].to(device)
            attention_mask = batch['attention_mask'].to(device)
            labels = batch['labels'].to(device).unsqueeze(1)

            outputs = model(input_ids=input_ids, attention_mask=attention_mask)
            loss = loss_fn(outputs.logits, labels)
            losses.append(loss.item())

            # ✅ sigmoid converts raw logit → probability in [0, 1]
            probs = torch.sigmoid(outputs.logits).cpu().numpy()
            predicted = (probs > 0.5).astype(int)
            preds.extend(predicted)
            true_labels.extend(labels.cpu().numpy())

    val_loss = sum(losses) / len(losses)
    accuracy = accuracy_score(true_labels, preds)
    precision, recall, f1, _ = precision_recall_fscore_support(
        true_labels, preds, average='binary', zero_division=0
    )
    return val_loss, accuracy, precision, recall, f1


def predict_url(model, tokenizer, url: str, device) -> float:
    """
    ✅ Canonical inference function — always returns a probability in [0.0, 1.0].
    Use this in your FastAPI backend to avoid the raw-logit bug.

    Example:
        score = predict_url(model, tokenizer, "https://google.com", DEVICE)
        risk_score = int(score * 100)  # 0-100
    """
    model.eval()
    encoding = tokenizer(
        url,
        add_special_tokens=True,
        max_length=MAX_LEN,
        return_token_type_ids=False,
        padding='max_length',
        truncation=True,
        return_attention_mask=True,
        return_tensors='pt',
    )
    input_ids = encoding['input_ids'].to(device)
    attention_mask = encoding['attention_mask'].to(device)

    with torch.no_grad():
        outputs = model(input_ids=input_ids, attention_mask=attention_mask)
        # ✅ MUST apply sigmoid — logits are NOT probabilities
        prob = torch.sigmoid(outputs.logits).item()

    return prob  # float in [0.0, 1.0]


def main():
    print(f"Using device: {DEVICE}")

    tokenizer = DistilBertTokenizerFast.from_pretrained(MODEL_NAME)
    model = DistilBertForSequenceClassification.from_pretrained(MODEL_NAME, num_labels=1)
    model = model.to(DEVICE)

    if not os.path.exists('data/train.csv') or not os.path.exists('data/val.csv'):
        print("Data files not found. Please run prepare_data.py first.")
        os.makedirs(MODEL_SAVE_DIR, exist_ok=True)
        torch.save(model.state_dict(), os.path.join(MODEL_SAVE_DIR, 'dummy_model.pt'))
        return

    train_data_loader = get_data_loader('data/train.csv', tokenizer, MAX_LEN, BATCH_SIZE)
    val_data_loader   = get_data_loader('data/val.csv',   tokenizer, MAX_LEN, BATCH_SIZE)

    optimizer = torch.optim.AdamW(model.parameters(), lr=LEARNING_RATE)

    os.makedirs('mlruns', exist_ok=True)
    mlflow.set_tracking_uri(r'sqlite:///mlruns/mlflow.db')
    mlflow.set_experiment("PhishGuard-DistilBERT")

    with mlflow.start_run():
        mlflow.log_params({
            "model_name": MODEL_NAME,
            "max_len": MAX_LEN,
            "batch_size": BATCH_SIZE,
            "epochs": EPOCHS,
            "learning_rate": LEARNING_RATE
        })

        best_f1 = 0

        for epoch in range(EPOCHS):
            print(f"--- Epoch {epoch + 1}/{EPOCHS} ---")

            train_loss = train_epoch(model, train_data_loader, optimizer, DEVICE, epoch + 1)
            print(f"Train Loss: {train_loss:.4f}")

            val_loss, val_acc, val_prec, val_rec, val_f1 = eval_model(
                model, val_data_loader, DEVICE
            )
            print(f"Val Loss: {val_loss:.4f} | Acc: {val_acc:.4f} | F1: {val_f1:.4f}")

            mlflow.log_metrics({
                "train_loss": train_loss,
                "val_loss": val_loss,
                "val_accuracy": val_acc,
                "val_precision": val_prec,
                "val_recall": val_rec,
                "val_f1": val_f1
            }, step=epoch + 1)

            if val_f1 > best_f1:
                best_f1 = val_f1
                print("Saving new best model checkpoint...")
                os.makedirs(MODEL_SAVE_DIR, exist_ok=True)
                tokenizer.save_pretrained(MODEL_SAVE_DIR)
                torch.save(model.state_dict(), os.path.join(MODEL_SAVE_DIR, 'pytorch_model.pt'))

        print(f"\nTraining complete. Best val F1: {best_f1:.4f}")


if __name__ == '__main__':
    main()