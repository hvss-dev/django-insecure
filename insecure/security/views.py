import json
import os
import base64

from django.http import HttpResponse, JsonResponse
from django.utils.safestring import mark_safe

from security.models import User


def unsafe_users(request, user_id):
    """Fixed SQL injection - now using ORM filter"""
    try:
        # Validate user_id is numeric
        user_id = int(user_id)
        users = User.objects.filter(id=user_id)
        if users.exists():
            return HttpResponse(f"User found: {users.first()}")
        else:
            return HttpResponse("User not found")
    except (ValueError, TypeError):
        return HttpResponse("Invalid user ID", status=400)


# http://127.0.0.1:8000/security/safe/users/1
def safe_users(request, user_id):
    """Uses parameterised query so it's fine"""

    users = User.objects.raw('SELECT * FROM security_user WHERE id = %s', (user_id,))

    return HttpResponse(users)


def read_file(request, filename):
    """Fixed path traversal - now validates file paths with dynamic directory"""
    import os.path
    
    # Use environment variable or fallback to secure directory
    ALLOWED_DIR = os.environ.get('SAFE_FILES_DIR', '/var/app/safe_files/')
    
    try:
        # Normalize and validate the path
        safe_path = os.path.join(ALLOWED_DIR, os.path.basename(filename))
        abs_path = os.path.abspath(safe_path)
        
        # Ensure the path is within allowed directory
        if not abs_path.startswith(os.path.abspath(ALLOWED_DIR)):
            return HttpResponse("Access denied: Invalid file path", status=403)
        
        # Check if file exists and is a file (not directory)
        if not os.path.isfile(abs_path):
            return HttpResponse("File not found", status=404)
            
        with open(abs_path, 'r', encoding='utf-8') as f:
            return HttpResponse(f.read())
    except (OSError, IOError) as e:
        return HttpResponse(f"Error reading file: {str(e)}", status=500)
    except Exception as e:
        return HttpResponse(f"Unexpected error: {str(e)}", status=500)


def copy_file(request, filename):
    """Fixed command injection - now using shutil for safe file operations"""
    import shutil
    import os.path
    import tempfile
    
    # Use environment variable or fallback to secure directory
    ALLOWED_DIR = os.environ.get('SAFE_FILES_DIR', '/var/app/safe_files/')
    
    try:
        # Validate and sanitize filename
        safe_filename = os.path.basename(filename)
        source_path = os.path.join(ALLOWED_DIR, safe_filename)
        dest_path = os.path.join(ALLOWED_DIR, f"new_{safe_filename}")
        
        # Ensure paths are within allowed directory
        if not os.path.abspath(source_path).startswith(os.path.abspath(ALLOWED_DIR)):
            return HttpResponse("Access denied: Invalid source path", status=403)
            
        if not os.path.isfile(source_path):
            return HttpResponse("Source file not found", status=404)
        
        # Use shutil.copy2() instead of subprocess - more secure
        shutil.copy2(source_path, dest_path)
        
        return HttpResponse(f"File copied successfully: {safe_filename} -> new_{safe_filename}")
        
    except (OSError, IOError) as e:
        return HttpResponse(f"Error copying file: {str(e)}", status=500)
    except Exception as e:
        return HttpResponse(f"Unexpected error: {str(e)}", status=500)


# Removed insecure hardcoded tokens and test data
# For secure token generation, use proper JWT libraries in production

from django.views.decorators.http import require_http_methods

@require_http_methods(["GET"])
def admin_index(request):
    """Fixed insecure deserialization - now using JSON tokens"""
    import json
    from django.contrib.auth.decorators import login_required
    
    try:
        # Get token from cookie
        token_b64 = request.COOKIES.get('secure_token', '')
        if not token_b64:
            return HttpResponse('No access token provided', status=401)
            
        # Decode and parse JSON (safe)
        token_json = base64.b64decode(token_b64).decode('utf-8')
        user_data = json.loads(token_json)
        
        # Validate token structure
        if not isinstance(user_data, dict) or 'perms' not in user_data:
            return HttpResponse('Invalid token format', status=401)
            
        # Check permissions
        if user_data.get('perms') == 1:
            return HttpResponse('Hello Admin')
        else:
            return HttpResponse('No access - insufficient permissions', status=403)
            
    except (json.JSONDecodeError, ValueError, TypeError) as e:
        return HttpResponse('Invalid token', status=401)
    except Exception as e:
        return HttpResponse('Authentication error', status=500)


# http://127.0.0.1:8000/security/search?query=%3Cscript%3Enew%20Image().src=%22http://127.0.0.1:8000/security/log?string=%22.concat(document.cookie)%3C/script%3E
@require_http_methods(["GET"])
def search(request):
    """Fixed XSS - now properly escapes output"""
    from django.utils.html import escape
    
    query = request.GET.get('query', '')
    
    # Escape HTML to prevent XSS
    safe_query = escape(query)
    
    response = HttpResponse(f"Query: {safe_query}")
    
    # Enable XSS protection (remove the dangerous override)
    response['X-XSS-Protection'] = '1; mode=block'
    response['Content-Security-Policy'] = "default-src 'self'"
    
    return response

@require_http_methods(["GET"])
def log(request):
    """Fixed logging - now uses proper logging and validates input"""
    import logging
    import re
    from django.utils.html import escape
    
    # Configure logger
    logger = logging.getLogger(__name__)
    
    string = request.GET.get('string', '')
    
    # Validate and sanitize input
    if len(string) > 1000:  # Limit log message size
        return HttpResponse('Log message too long', status=400)
    
    # Sanitize input to prevent log injection
    # Remove control characters and newlines that could break log format
    sanitized_string = re.sub(r'[\r\n\t\x00-\x1f\x7f-\x9f]', '', string)
    
    # Further limit to alphanumeric and basic punctuation
    sanitized_string = re.sub(r'[^a-zA-Z0-9\s.,!?-]', '', sanitized_string)
    
    # Truncate if still too long after sanitization
    sanitized_string = sanitized_string[:100]
    
    # Log only a hash of the user input for security audit purposes
    import hashlib
    input_hash = hashlib.sha256(string.encode('utf-8')).hexdigest()[:16]
    
    # Log without user-controlled data directly
    logger.info(f"User log request received - Input hash: {input_hash}, Length: {len(string)}")
    
    return HttpResponse('Logged successfully')
