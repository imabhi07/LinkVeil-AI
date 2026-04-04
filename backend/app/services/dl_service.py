import torch
import os
import logging
from transformers import DistilBertTokenizerFast, DistilBertForSequenceClassification

logger = logging.getLogger(__name__)

class DLService:
    def __init__(self):
        self.model_dir = "ml/models/distilbert-phish"
        self.model_name = "distilbert-base-uncased"
        self.max_len = 128
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        
        self.tokenizer = None
        self.model = None
        self._load_model()
        
    def _load_model(self):
        try:
            if os.path.exists(os.path.join(self.model_dir, 'pytorch_model.pt')):
                logger.info(f"Loading local DistilBERT model weights from {self.model_dir}")
                self.tokenizer = DistilBertTokenizerFast.from_pretrained(self.model_dir)
                
                # Instantiate base architecture
                self.model = DistilBertForSequenceClassification.from_pretrained(self.model_name, num_labels=1)
                
                # Apply fine-tuned state dictionary
                state_dict = torch.load(os.path.join(self.model_dir, 'pytorch_model.pt'), map_location=self.device, weights_only=True)
                self.model.load_state_dict(state_dict, strict=False)
                logger.info("Successfully loaded fine-tuned PyTorch weights.")
            else:
                logger.warning(f"Local model not found at {self.model_dir}. Falling back to HuggingFace base model for predictions.")
                self.tokenizer = DistilBertTokenizerFast.from_pretrained(self.model_name)
                self.model = DistilBertForSequenceClassification.from_pretrained(self.model_name, num_labels=1)
                
            self.model.to(self.device)
            self.model.eval()
            
        except Exception as e:
            logger.error(f"Failed to load DL model: {e}")
            raise
            
    def predict(self, url: str) -> float:
        """
        Takes a URL string and returns a phishing probability between 0.0 and 1.0.
        Synchronous, CPU/GPU bound.
        """
        if not self.model or not self.tokenizer:
            logger.error("Predict called before model loaded.")
            return 0.5
            
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
                outputs = self.model(
                    input_ids=input_ids,
                    attention_mask=attention_mask
                )
                
            # Convert logit to probability
            probs = torch.sigmoid(outputs.logits).cpu().numpy().flatten()
            logger.info(f"Raw DL prob for '{url}': {probs[0]:.4f}")
            return float(probs[0])
            
        except Exception as e:
            logger.error(f"Error during DL prediction for {url}: {e}")
            return 0.5 # Safe/Unsure fallback

# Singleton instance to be imported by engine
dl_service = DLService()
