import pytest
from unittest.mock import patch, MagicMock
from backend.app.services.dl_service import DLService

@pytest.fixture
def mock_dl_service():
    with patch('backend.app.services.dl_service.DistilBertForSequenceClassification.from_pretrained') as mock_model, \
         patch('backend.app.services.dl_service.DistilBertTokenizerFast.from_pretrained') as mock_tokenizer:
         
        # Mock PyTorch outputs
        mock_outputs = MagicMock()
        import torch
        # A logit of 0 corresponds to a probability of 0.5 via sigmoid
        mock_outputs.logits = torch.tensor([[0.0]])
        mock_model.return_value.return_value = mock_outputs
         
        # Ensure we avoid loading live weights for fast unit tests
        with patch('torch.load'):
             service = DLService()
             
             # Patch the call to the model
             service.model = MagicMock(return_value=mock_outputs)
             
             yield service

def test_dl_predict_mocked(mock_dl_service):
    # Logit 0.0 -> Sigmoid -> 0.5
    prob = mock_dl_service.predict("http://test-url.com")
    
    # We expect float parsing back natively
    assert isinstance(prob, float)
    assert round(prob, 2) == 0.50

def test_dl_predict_fallback_on_error(mock_dl_service):
    mock_dl_service.model.side_effect = Exception("Inference Error")
    
    # A crash should gracefully fallback to 0.5 (unsure logic) to not crash the engine
    prob = mock_dl_service.predict("http://crash-test.com")
    assert prob == 0.5
