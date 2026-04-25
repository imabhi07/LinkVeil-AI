import pytest
import os
import json
from unittest.mock import MagicMock, AsyncMock, patch
from PIL import Image, ImageDraw
from backend.app.services.vision_service import VisionService

@pytest.fixture
def vision_service():
    return VisionService()

@pytest.fixture
def mock_screenshot():
    path = "data/test_screenshot.png"
    os.makedirs("data", exist_ok=True)
    img = Image.new("RGB", (100, 100), color="white")
    draw = ImageDraw.Draw(img)
    draw.text((10, 10), "TEST", fill="black")
    img.save(path)
    yield path
    if os.path.exists(path):
        os.remove(path)

@pytest.mark.asyncio
async def test_vision_analyze_success(vision_service, mock_screenshot):
    # Mock the Gemini client and response
    mock_response = MagicMock()
    mock_response.text = json.dumps({
        "brand_logo_guess": "Netflix",
        "confidence": 0.95
    })
    
    mock_client = MagicMock()
    mock_client.aio.models.generate_content = AsyncMock(return_value=mock_response)
    
    with patch('backend.app.services.vision_service._get_client', return_value=mock_client):
        result = await vision_service.analyze_screenshot(mock_screenshot)
        
        assert result["visual_score"] == 0.95
        assert result["brand_logo_guess"] == "Netflix"
        assert result["phash"] == "AI-VISION-MATCH"

@pytest.mark.asyncio
async def test_vision_analyze_no_match(vision_service, mock_screenshot):
    mock_response = MagicMock()
    mock_response.text = json.dumps({
        "brand_logo_guess": None,
        "confidence": 0.1
    })
    
    mock_client = MagicMock()
    mock_client.aio.models.generate_content = AsyncMock(return_value=mock_response)
    
    with patch('backend.app.services.vision_service._get_client', return_value=mock_client):
        result = await vision_service.analyze_screenshot(mock_screenshot)
        
        assert result["visual_score"] == 0.1
        assert result["brand_logo_guess"] is None

@pytest.mark.asyncio
async def test_vision_analyze_client_none(vision_service, mock_screenshot):
    # Test behavior when API key is missing
    with patch('backend.app.services.vision_service._get_client', return_value=None):
        result = await vision_service.analyze_screenshot(mock_screenshot)
        assert result["visual_score"] == 0.0
        assert result["brand_logo_guess"] is None
