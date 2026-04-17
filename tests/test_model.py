import pytest
import torch
import os
from transformers import DistilBertTokenizerFast, DistilBertForSequenceClassification

def test_distilbert_initialization():
    """Verify that DistilBERT from HuggingFace can be loaded locally or dynamically."""
    model_name = "distilbert-base-uncased"
    tokenizer = DistilBertTokenizerFast.from_pretrained(model_name)
    model = DistilBertForSequenceClassification.from_pretrained(model_name, num_labels=1)
    
    assert tokenizer is not None
    assert model is not None
    
def test_distilbert_forward_pass():
    """Verify the binary classification head architecture yields expected shape logits."""
    model_name = "distilbert-base-uncased"
    tokenizer = DistilBertTokenizerFast.from_pretrained(model_name)
    model = DistilBertForSequenceClassification.from_pretrained(model_name, num_labels=1)
    
    # Dummy URL input
    inputs = tokenizer("http://secure-login.com", return_tensors="pt")
    
    # Forward pass without grad since we're just testing graph
    with torch.no_grad():
        outputs = model(**inputs)
        
    logits = outputs.logits
    # With num_labels=1, shape should be (1, 1) for a single batch element
    assert logits.shape == (1, 1)

def test_model_directory_creation():
    """Verify creating the save structure for the model."""
    os.makedirs('ml/models/test-dir', exist_ok=True)
    assert os.path.exists('ml/models/test-dir')
    # cleanup 
    os.rmdir('ml/models/test-dir')
