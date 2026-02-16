import json
import time
import base64
import os
import requests
import argparse
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from urllib.parse import urlencode
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class VertexAIClient:
    """
    A client for making authenticated requests to Google Vertex AI API.
    Handles service account authentication via JWT tokens and token caching.
    """
    
    def __init__(self, service_account_path=None, config_path=None):
        """
        Initialize the VertexAI client.

        Args:
            service_account_path (str, optional): Path to sa.json. Defaults to ./sa.json
            config_path (str, optional): Path to config.json. Defaults to ./config.json
        """
        self.service_account_path = service_account_path or "./sa.json"
        self.config_path = config_path or "./config.json"
        self.service_account_key = self._load_service_account()
        self.llm_config = self._load_config()
        self.cached_token = None
        self.token_expiry = None
        
    def _load_service_account(self) -> dict:
        """Load and parse the service account JSON file."""
        try:
            with open(self.service_account_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            raise FileNotFoundError(f"Service account file not found: {self.service_account_path}")
        except json.JSONDecodeError:
            raise ValueError(f"Invalid JSON in service account file: {self.service_account_path}")
    
    def _load_config(self) -> dict:
        """Load and parse the LLM configuration JSON file."""
        try:
            with open(self.config_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            raise FileNotFoundError(f"Config file not found: {self.config_path}")
        except json.JSONDecodeError:
            raise ValueError(f"Invalid JSON in config file: {self.config_path}")
    
    def _create_signed_jwt(self) -> str:
        """
        Create a signed JWT for service account authentication.
        
        Returns:
            str: Base64-encoded signed JWT
        """
        header = {
            "alg": "RS256",
            "typ": "JWT"
        }
        
        now = int(time.time())
        expires = now + 3600  # Token valid for 1 hour
        
        claim_set = {
            "iss": self.service_account_key["client_email"],
            "scope": "https://www.googleapis.com/auth/cloud-platform",
            "aud": self.service_account_key["token_uri"],
            "exp": expires,
            "iat": now
        }
        
        # Encode header and claim set
        encoded_header = base64.urlsafe_b64encode(
            json.dumps(header, separators=(',', ':')).encode('utf-8')
        ).decode('utf-8').rstrip('=')
        
        encoded_claim_set = base64.urlsafe_b64encode(
            json.dumps(claim_set, separators=(',', ':')).encode('utf-8')
        ).decode('utf-8').rstrip('=')
        
        unsigned_jwt = f"{encoded_header}.{encoded_claim_set}"
        
        try:
            # Load the private key
            private_key = serialization.load_pem_private_key(
                self.service_account_key["private_key"].encode('utf-8'),
                password=None,
                backend=default_backend()
            )
            
            # Sign the JWT
            signature = private_key.sign(
                unsigned_jwt.encode('utf-8'),
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            
            # Encode signature
            encoded_signature = base64.urlsafe_b64encode(signature).decode('utf-8').rstrip('=')
            
            return f"{unsigned_jwt}.{encoded_signature}"
            
        except Exception as e:
            logger.error(f"Error signing JWT: {e}")
            if '\\n' not in self.service_account_key["private_key"]:
                logger.warning("Private key might be missing newline characters")
            raise
    
    def _exchange_jwt_for_token(self, signed_jwt: str) -> dict:
        """
        Exchange the signed JWT for an OAuth2 access token.
        
        Args:
            signed_jwt (str): The signed JWT
            
        Returns:
            dict: Token response containing access_token and expires_in
        """
        token_url = self.service_account_key["token_uri"]
        
        payload = {
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": signed_jwt
        }
        
        headers = {
            "Content-Type": "application/x-www-form-urlencoded"
        }
        
        try:
            response = requests.post(
                token_url,
                data=urlencode(payload),
                headers=headers,
                timeout=30
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"Error exchanging JWT for token. Status: {response.status_code}, Body: {response.text}")
                response.raise_for_status()
                
        except requests.RequestException as e:
            logger.error(f"Exception during token exchange request: {e}")
            raise
    
    def get_access_token(self) -> str:
        """
        Get a valid OAuth2 access token for the service account.
        Uses caching to reuse tokens until expiration.
        
        Returns:
            str: The OAuth2 access token
        """
        # Check if we have a cached token that's still valid
        if (self.cached_token and self.token_expiry and 
            datetime.now() < self.token_expiry):
            logger.info("Using cached access token")
            return self.cached_token
        
        logger.info("No valid cached token found, requesting a new one")
        
        # Create and sign JWT
        jwt = self._create_signed_jwt()
        if not jwt:
            raise RuntimeError("Failed to create signed JWT")
        
        # Exchange JWT for access token
        token_response = self._exchange_jwt_for_token(jwt)
        if not token_response or "access_token" not in token_response:
            logger.error(f"Failed to exchange JWT for token. Response: {token_response}")
            raise RuntimeError("Failed to retrieve access token from Google")
        
        # Cache the token
        self.cached_token = token_response["access_token"]
        expires_in = token_response.get("expires_in", 3600)
        
        # Set expiry with a 60-second buffer
        self.token_expiry = datetime.now() + timedelta(seconds=max(1, expires_in - 60))
        
        logger.info("New access token obtained and cached")
        return self.cached_token
    
    def call_vertex_ai(self, prompt: str, temperature: float = 0.7, max_output_tokens: int = 4096) -> dict:
        """
        Make an inference call to Vertex AI.
        
        Args:
            prompt (str): The text prompt to send to the model
            temperature (float): Controls randomness in the response (0.0 to 1.0)
            max_output_tokens (int): Maximum number of tokens in the response
            
        Returns:
            dict: The response from Vertex AI API
        """
        access_token = self.get_access_token()
        
        # Build the API URL
        url = (f"https://{self.llm_config['location']}-aiplatform.googleapis.com/v1/"
               f"projects/{self.llm_config['projectId']}/locations/{self.llm_config['location']}/"
               f"publishers/google/models/{self.llm_config['modelId']}:generateContent")
        base_url = f"https://{self.llm_config['location']}-aiplatform.googleapis.com/v1/projects/{self.llm_config['projectId']}/locations/{self.llm_config['location']}/endpoints/openapi"

        print(f"export LLM_URL={base_url}")
        print(f"export LLM_API_TOKEN={access_token}")
        
        # Prepare the payload
        payload = {}
        
        # Prepare headers
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }
        
        # For this script, we just need the credentials, not an actual API call
        # Return a simple success response to avoid JSON parsing errors
        return {"status": "credentials_generated", "url": base_url, "token_length": len(access_token)}


# Example usage
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Get Vertex AI API credentials")
    parser.add_argument(
        "--sa", "--service-account",
        dest="service_account_path",
        help="Path to service account JSON file (default: ./sa.json)"
    )
    parser.add_argument(
        "--config",
        dest="config_path",
        help="Path to config JSON file (default: ./config.json)"
    )

    args = parser.parse_args()

    # Initialize the client with provided or default paths
    client = VertexAIClient(
        service_account_path=args.service_account_path,
        config_path=args.config_path
    )

    # Make an inference call to get the API credentials
    try:
        response = client.call_vertex_ai("What is the capital of France?")
        print("Response:", response)
    except Exception as e:
        print(f"Error: {e}")
