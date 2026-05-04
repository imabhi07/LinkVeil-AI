import os
import torch
import logging
from typing import Optional
from transformers import DistilBertTokenizerFast, DistilBertForSequenceClassification

logging.getLogger("transformers.modeling_utils").setLevel(logging.ERROR)
logger = logging.getLogger(__name__)

class DLService:
    def __init__(self):
        self.model_name = 'distilbert-base-uncased'
        self.max_len = 128
        self.model_dir = "ml/models/distilbert-phish"
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        
        self.tokenizer = None
        self.model = None
        
        self._load_model()

    def _load_model(self):
        try:
            model_path = os.path.join(self.model_dir, "pytorch_model.pt")
            if not os.path.exists(model_path):
                logger.warning(f"DistilBERT model not found at {model_path}. "
                             "Run python ml/train.py first. DL inference will be disabled.")
                return

            self.tokenizer = DistilBertTokenizerFast.from_pretrained(self.model_dir)
            self.model = DistilBertForSequenceClassification.from_pretrained(
                self.model_name, 
                num_labels=1
            )
            
            # Load the fine-tuned weights
            self.model.load_state_dict(torch.load(model_path, map_location=self.device))
            self.model.to(self.device)
            self.model.eval()
            
            logger.info(f"Loaded DistilBERT model from {self.model_dir} on {self.device}")

        except Exception as e:
            logger.error(f"Failed to load DistilBERT model: {e}")
            self.model = None

    def predict(self, url: str) -> Optional[float]:
        """
        Returns phishing probability in [0.0, 1.0].
        None returned as fallback if model is unavailable.
        """
        if self.model is None or self.tokenizer is None:
            return None

        try:
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

            input_ids = encoding['input_ids'].to(self.device)
            attention_mask = encoding['attention_mask'].to(self.device)

            with torch.no_grad():
                outputs = self.model(input_ids=input_ids, attention_mask=attention_mask)
                prob = torch.sigmoid(outputs.logits).item()

            logger.info(f"BERT prob for '{url}': {prob:.4f}")
            return prob

        except Exception as e:
            logger.error(f"DLService.predict error for '{url}': {e}")
            return 0.5

# Singleton instance
dl_service = DLService()
