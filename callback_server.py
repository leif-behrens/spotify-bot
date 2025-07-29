#!/usr/bin/env python3
"""
Separater Callback Server für Spotify OAuth
Läuft auf Port 4444 für Spotify-Callbacks
"""

import os
import sys
import logging
from flask import Flask, request, redirect, url_for, session, jsonify
from urllib.parse import urlencode
import spotipy
from spotipy.oauth2 import SpotifyOAuth

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

try:
    from src.config import ConfigManager
    from src.spotify_auth import SpotifyAuthenticator
except ImportError as e:
    print(f"Import error: {e}")
    sys.exit(1)

# Flask App für Callbacks
callback_app = Flask(__name__)
callback_app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'your-secret-key')

# Logging setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global config
config = None
spotify_auth = None

def init_app():
    """Initialize the callback app with config"""
    global config, spotify_auth
    
    try:
        config = ConfigManager()
        spotify_auth = SpotifyAuthenticator(config)
        logger.info("Callback server initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize callback server: {e}")
        raise

@callback_app.route('/callback')
def spotify_callback():
    """Handle Spotify OAuth callback"""
    try:
        # Get authorization code from callback
        code = request.args.get('code')
        error = request.args.get('error')
        
        if error:
            logger.error(f"Spotify authorization error: {error}")
            return f"Authorization failed: {error}", 400
            
        if not code:
            logger.error("No authorization code received")
            return "No authorization code received", 400
            
        logger.info(f"Received authorization code: {code[:10]}...")
        
        # Exchange code for tokens
        try:
            # Get token using SpotifyAuth
            success = spotify_auth.authenticate_with_code(code)
            
            if success:
                logger.info("Successfully authenticated with Spotify")
                
                # Redirect to main dashboard with success message
                dashboard_url = "https://localhost/?auth=success"
                dashboard_base_url = "https://localhost"
                
                return f"""
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Spotify Authentication Successful</title>
                    <meta charset="utf-8">
                    <style>
                        body {{ 
                            font-family: Arial, sans-serif; 
                            text-align: center; 
                            padding: 50px;
                            background: linear-gradient(135deg, #1db954, #1ed760);
                            color: white;
                        }}
                        .container {{ 
                            max-width: 500px; 
                            margin: 0 auto;
                            background: rgba(0,0,0,0.2);
                            padding: 30px;
                            border-radius: 10px;
                        }}
                        .success {{ color: #1db954; font-size: 24px; margin-bottom: 20px; }}
                        .button {{ 
                            background: #1db954; 
                            color: white; 
                            padding: 12px 24px; 
                            text-decoration: none; 
                            border-radius: 25px;
                            display: inline-block;
                            margin-top: 20px;
                        }}
                        .button:hover {{ background: #1ed760; }}
                    </style>
                </head>
                <body>
                    <div class="container">
                        <h1>🎵 Spotify Authentication Successful!</h1>
                        <p>Your Spotify account has been successfully connected.</p>
                        <p>You can now close this window and return to the dashboard.</p>
                        <a href="{dashboard_url}" class="button">Go to Dashboard</a>
                        
                        <script>
                        // Try to start service automatically
                        fetch("{dashboard_base_url}/service/start-after-auth", {{
                            method: 'POST',
                            headers: {{
                                'Content-Type': 'application/json',
                            }}
                        }})
                        .then(response => response.json())
                        .then(data => {{
                            console.log('Service start result:', data);
                            if (data.success) {{
                                document.querySelector('p').innerHTML = 'Service wurde automatisch gestartet! Sie können das Fenster schließen.';
                            }}
                        }})
                        .catch(error => {{
                            console.error('Failed to start service:', error);
                        }});
                        
                        // Auto-redirect after 3 seconds
                        setTimeout(function() {{
                            window.location.href = "{dashboard_url}";
                        }}, 3000);
                        </script>
                    </div>
                </body>
                </html>
                """
            else:
                logger.error("Failed to authenticate with Spotify")
                return "Authentication failed", 500
                
        except Exception as e:
            logger.error(f"Error during token exchange: {e}")
            return f"Authentication error: {str(e)}", 500
            
    except Exception as e:
        logger.error(f"Callback error: {e}")
        return f"Callback error: {str(e)}", 500

@callback_app.route('/health')
def health_check():
    """Health check endpoint"""
    return jsonify({"status": "healthy", "service": "callback-server"}), 200

@callback_app.route('/')
def callback_info():
    """Info page for callback server"""
    return jsonify({
        "service": "Spotify Callback Server",
        "port": 4444,
        "endpoints": {
            "/callback": "Spotify OAuth callback",
            "/health": "Health check"
        }
    })

if __name__ == '__main__':
    try:
        init_app()
        
        # Run callback server on port 4444
        callback_app.run(
            host='0.0.0.0',
            port=4444,
            debug=False,
            threaded=True
        )
    except Exception as e:
        logger.error(f"Failed to start callback server: {e}")
        sys.exit(1)