# Update airflow from 2.3.2 to 2.10
_Exported on 28/07/2025 at 12:53:22 GMT+5:30 from Cursor (1.2.4)_

---

**User**

I am want to plan to update airflow 2.3.2 to airflow 2.10 and here the details for airflow 2.3.2 "here my details for airflow2.3.2 and give me what changes required for airflow 2.10"auth_backend = airflow.api.auth.backend.default and AIRFLOW__WEBSERVER__AUTH__BACKEND=cibdaos_XXXXXX_airflow_ida.fab.security.AirflowOIDSecurityManager and in ida.py class i am using IDAAuth and security.py class i am using diff classes OpenIDEConnnect2 and oidc_error and OIDCSecurityManagerMixin and  AUTHIDCVier i am using AirflowOIDCSecurityManager and roles list i can see Admin and Op and public and User and Viewer and webserverconfig AUTH_TYPE=AUTH_REMOTE_USER and SECURITY_MANAGER_CLASS = AirflowOIDCSecurityManager and i dont see OPY your ide.py and security.py but required packsges in run -y install ""--Please create ide.py and security.py to authenticate airflow UI and give me sample docker file to create image 

---

**Cursor**

You want to upgrade from **Airflow 2.3.2** to **Airflow 2.10** and need to migrate your custom authentication setup, which uses a custom `AirflowOIDCSecurityManager` and related classes in `ida.py` and `security.py`. You also want a sample Dockerfile for Airflow 2.10 with these customizations.

Let's break this down:

---

## 1. **Airflow Auth Changes (2.3.2 → 2.10)**

- **Airflow 2.10** still uses Flask AppBuilder (FAB) for authentication, but there are some changes and deprecations.
- The config variable `SECURITY_MANAGER_CLASS` is still supported.
- The `AUTH_TYPE` variable is still used, but you should set `SECURITY_MANAGER_CLASS` for custom OIDC.
- The `auth_backend` for the API is still supported, but you may want to use the new RBAC features and check for any deprecations in your custom code.
- **OIDC** (OpenID Connect) is still supported via custom security managers.

---

## 2. **Required Files**

You need:
- `ida.py` (with `IDAAuth`)
- `security.py` (with `OpenIDConnect2`, `oidc_error`, `OIDCSecurityManagerMixin`, `AUTHIDCVier`, `AirflowOIDCSecurityManager`)

Below are **template examples** for these files, which you should adapt to your actual OIDC provider and logic.

---

### **ida.py** (Example)

```python
# ida.py
from flask_appbuilder.security.manager import AUTH_REMOTE_USER

class IDAAuth:
    """
    Example custom authentication class for Airflow OIDC.
    """
    def authenticate(self, username, password):
        # Implement your custom authentication logic here
        # For OIDC, you may not need password-based auth
        return username
```

---

### **security.py** (Example)

```python
# security.py
from flask_appbuilder.security.manager import AUTH_REMOTE_USER, BaseSecurityManager

class OpenIDConnect2:
    # Implement your OIDC logic here
    pass

def oidc_error():
    # Handle OIDC errors
    pass

class OIDCSecurityManagerMixin:
    # Mixin for OIDC logic
    pass

class AUTHIDCVier:
    # Implement your custom verifier logic
    pass

class AirflowOIDCSecurityManager(OIDCSecurityManagerMixin, BaseSecurityManager):
    """
    Custom Security Manager for Airflow using OIDC.
    """
    AUTH_TYPE = AUTH_REMOTE_USER

    def __init__(self, appbuilder):
        super().__init__(appbuilder)
        # Initialize OIDC logic here
```

---

## 3. **airflow.cfg / Environment Variables**

Set these in your Dockerfile or environment:

```ini
# airflow.cfg or as env vars
[webserver]
# Use your custom security manager
SECURITY_MANAGER_CLASS = security.AirflowOIDCSecurityManager
AUTH_TYPE = AUTH_REMOTE_USER
```

Or as environment variables:

```bash
AIRFLOW__WEBSERVER__SECURITY_MANAGER_CLASS=security.AirflowOIDCSecurityManager
AIRFLOW__WEBSERVER__AUTH_TYPE=AUTH_REMOTE_USER
```

---

## 4. **Sample Dockerfile for Airflow 2.10 with Custom Auth**

```dockerfile
FROM apache/airflow:2.10.0-python3.10

USER root
# Install OIDC and other dependencies
RUN pip install flask_appbuilder[oidc] flask_oidc

# Copy your custom auth files
COPY ida.py /opt/airflow/ida.py
COPY security.py /opt/airflow/security.py

# Set environment variables for Airflow config
ENV AIRFLOW__WEBSERVER__SECURITY_MANAGER_CLASS=security.AirflowOIDCSecurityManager
ENV AIRFLOW__WEBSERVER__AUTH_TYPE=AUTH_REMOTE_USER

USER airflow
```

---

## 5. **What to Check/Update for Airflow 2.10**

- **Check for breaking changes** in Flask AppBuilder and Airflow security manager APIs.
- **Test your custom security manager** with Airflow 2.10, as some method signatures or hooks may have changed.
- **Update your requirements** to ensure all dependencies are compatible with Airflow 2.10.
- **Review Airflow 2.10 release notes** for any changes to authentication or RBAC.

---

## 6. **Roles**

Your roles (Admin, Op, public, User, Viewer) are still valid. You may want to review role permissions in the Airflow UI after upgrade.

---

## 7. **Summary Table**

| What you have (2.3.2) | What you need (2.10) | Notes |
|-----------------------|----------------------|-------|
| `SECURITY_MANAGER_CLASS` | Same | Update import path if needed |
| `AUTH_TYPE=AUTH_REMOTE_USER` | Same | |
| Custom OIDC classes | Same, but check for API changes | |
| `auth_backend` for API | Same | |
| Roles | Same | Review permissions |

---

## 8. **Next Steps**

1. Place the provided `ida.py` and `security.py` in your Airflow project.
2. Use the Dockerfile to build your custom Airflow image.
3. Test authentication and UI login.
4. Adjust the custom classes as needed for your OIDC provider.

---

Would you like me to generate more detailed code for `ida.py` and `security.py` with OIDC logic, or do you want to adapt these templates yourself? If you provide your actual OIDC provider details, I can make the code more specific.

```python
# ida.py
from flask_appbuilder.security.manager import AUTH_REMOTE_USER

class IDAAuth:
    """
    Example custom authentication class for Airflow OIDC.
    """
    def authenticate(self, username, password):
        # Implement your custom authentication logic here
        # For OIDC, you may not need password-based auth
        return username
```

```python
# security.py
from flask_appbuilder.security.manager import AUTH_REMOTE_USER, BaseSecurityManager

class OpenIDConnect2:
    # Implement your OIDC logic here
    pass

def oidc_error():
    # Handle OIDC errors
    pass

class OIDCSecurityManagerMixin:
    # Mixin for OIDC logic
    pass

class AUTHIDCVier:
    # Implement your custom verifier logic
    pass

class AirflowOIDCSecurityManager(OIDCSecurityManagerMixin, BaseSecurityManager):
    """
    Custom Security Manager for Airflow using OIDC.
    """
    AUTH_TYPE = AUTH_REMOTE_USER

    def __init__(self, appbuilder):
        super().__init__(appbuilder)
        # Initialize OIDC logic here
```

```ini
# airflow.cfg or as env vars
[webserver]
# Use your custom security manager
SECURITY_MANAGER_CLASS = security.AirflowOIDCSecurityManager
AUTH_TYPE = AUTH_REMOTE_USER
```

```shellscript
AIRFLOW__WEBSERVER__SECURITY_MANAGER_CLASS=security.AirflowOIDCSecurityManager
AIRFLOW__WEBSERVER__AUTH_TYPE=AUTH_REMOTE_USER
```

```dockerfile
FROM apache/airflow:2.10.0-python3.10

USER root
# Install OIDC and other dependencies
RUN pip install flask_appbuilder[oidc] flask_oidc

# Copy your custom auth files
COPY ida.py /opt/airflow/ida.py
COPY security.py /opt/airflow/security.py

# Set environment variables for Airflow config
ENV AIRFLOW__WEBSERVER__SECURITY_MANAGER_CLASS=security.AirflowOIDCSecurityManager
ENV AIRFLOW__WEBSERVER__AUTH_TYPE=AUTH_REMOTE_USER

USER airflow
```

---

**User**

Please generate more detailed code for ida.py with OIDC logic

create updated versions of your custom security manager classes, or do you need more specific guidance on any of these migration steps?

---

**Cursor**

Here’s how you can **create updated versions of your custom security manager classes for Airflow 2.10** with OIDC support, along with guidance for migration:

---

## 1. **General Migration Guidance**

- **Airflow 2.10** still uses Flask AppBuilder (FAB) for authentication, but you should check for any API changes in FAB and Airflow’s security manager.
- Your custom security manager should inherit from `flask_appbuilder.security.manager.BaseSecurityManager` (or the appropriate OIDC mixin if you use one).
- The `SECURITY_MANAGER_CLASS` config is still supported.
- OIDC logic is best handled using a mixin or by extending the security manager directly.
- Make sure your requirements include `flask_appbuilder[oidc]` and `flask_oidc`.

---

## 2. **Sample: Updated Custom Security Manager for OIDC (security.py)**

Below is a robust template for a custom OIDC security manager for Airflow 2.10.  
**You should adapt this to your actual OIDC provider and logic.**

```python
# security.py
from flask_appbuilder.security.manager import AUTH_REMOTE_USER, BaseSecurityManager
from flask_oidc import OpenIDConnect

class OIDCSecurityManagerMixin:
    def oidc_init_app(self, app):
        self.oidc = OpenIDConnect(app)

    def get_user(self, username):
        # Implement user lookup logic
        return self.find_user(username=username)

    def authenticate(self, username, password):
        # OIDC usually does not use password here, but you can implement fallback logic
        return self.get_user(username)

    def is_user_authenticated(self):
        return self.oidc.user_loggedin

    def get_user_info(self):
        return self.oidc.user_getinfo(['preferred_username', 'email', 'sub'])

class AirflowOIDCSecurityManager(OIDCSecurityManagerMixin, BaseSecurityManager):
    AUTH_TYPE = AUTH_REMOTE_USER

    def __init__(self, appbuilder):
        super().__init__(appbuilder)
        self.oidc_init_app(appbuilder.get_app)
```

---

## 3. **Sample: ida.py (if you need a custom auth class)**

```python
# ida.py
class IDAAuth:
    def authenticate(self, username, password):
        # For OIDC, you may not need this, but you can implement fallback logic
        return username
```

---

## 4. **airflow.cfg / Environment Variables**

Set these in your Dockerfile or environment:

```bash
AIRFLOW__WEBSERVER__SECURITY_MANAGER_CLASS=security.AirflowOIDCSecurityManager
AIRFLOW__WEBSERVER__AUTH_TYPE=AUTH_REMOTE_USER
```

---

## 5. **requirements.txt**

Add:
```
apache-airflow==2.10.0
flask_appbuilder[oidc]
flask_oidc
```

---

## 6. **Dockerfile (snippet)**

```dockerfile
FROM apache/airflow:2.10.0-python3.10

USER root
RUN pip install flask_appbuilder[oidc] flask_oidc

COPY security.py /opt/airflow/security.py
COPY ida.py /opt/airflow/ida.py

ENV AIRFLOW__WEBSERVER__SECURITY_MANAGER_CLASS=security.AirflowOIDCSecurityManager
ENV AIRFLOW__WEBSERVER__AUTH_TYPE=AUTH_REMOTE_USER

USER airflow
```

---

## 7. **OIDC Configuration**

You’ll need to add OIDC config to your Airflow webserver config (or as environment variables), e.g.:

```python
# In your airflow.cfg or as environment variables
OIDC_CLIENT_SECRETS = "/path/to/client_secrets.json"
OIDC_SCOPES = ["openid", "email", "profile"]
OIDC_RESOURCE_SERVER_ONLY = True
```

---

## 8. **Roles**

Your roles (Admin, Op, public, User, Viewer) will still work. You may want to review permissions in the Airflow UI after upgrade.

---

## 9. **Testing**

- After migration, test login and role assignment.
- Check Airflow and Flask AppBuilder logs for any errors or deprecation warnings.

---

**If you need a more specific implementation (e.g., with your actual OIDC provider, custom claims, or user mapping), please provide those details and I’ll tailor the code further.**  
Otherwise, you can use these templates as a starting point for your Airflow 2.10 migration!

```python
# security.py
from flask_appbuilder.security.manager import AUTH_REMOTE_USER, BaseSecurityManager
from flask_oidc import OpenIDConnect

class OIDCSecurityManagerMixin:
    def oidc_init_app(self, app):
        self.oidc = OpenIDConnect(app)

    def get_user(self, username):
        # Implement user lookup logic
        return self.find_user(username=username)

    def authenticate(self, username, password):
        # OIDC usually does not use password here, but you can implement fallback logic
        return self.get_user(username)

    def is_user_authenticated(self):
        return self.oidc.user_loggedin

    def get_user_info(self):
        return self.oidc.user_getinfo(['preferred_username', 'email', 'sub'])

class AirflowOIDCSecurityManager(OIDCSecurityManagerMixin, BaseSecurityManager):
    AUTH_TYPE = AUTH_REMOTE_USER

    def __init__(self, appbuilder):
        super().__init__(appbuilder)
        self.oidc_init_app(appbuilder.get_app)
```

```python
# ida.py
class IDAAuth:
    def authenticate(self, username, password):
        # For OIDC, you may not need this, but you can implement fallback logic
        return username
```

```shellscript
AIRFLOW__WEBSERVER__SECURITY_MANAGER_CLASS=security.AirflowOIDCSecurityManager
AIRFLOW__WEBSERVER__AUTH_TYPE=AUTH_REMOTE_USER
```

```plaintext
apache-airflow==2.10.0
flask_appbuilder[oidc]
flask_oidc
```

```dockerfile
FROM apache/airflow:2.10.0-python3.10

USER root
RUN pip install flask_appbuilder[oidc] flask_oidc

COPY security.py /opt/airflow/security.py
COPY ida.py /opt/airflow/ida.py

ENV AIRFLOW__WEBSERVER__SECURITY_MANAGER_CLASS=security.AirflowOIDCSecurityManager
ENV AIRFLOW__WEBSERVER__AUTH_TYPE=AUTH_REMOTE_USER

USER airflow
```

```python
# In your airflow.cfg or as environment variables
OIDC_CLIENT_SECRETS = "/path/to/client_secrets.json"
OIDC_SCOPES = ["openid", "email", "profile"]
OIDC_RESOURCE_SERVER_ONLY = True
```

"""
Airflow 2.10 Webserver Configuration
Updated for modern Flask-AppBuilder and OIDC authentication
"""

import os
from flask_appbuilder.security.manager import AUTH_REMOTE_USER, AUTH_OAUTH

# Import your custom security manager
from cibdaos_xxxx_airflow_ida.fab.security import AirflowOIDCSecurityManager

# =============================================================================
# Authentication Configuration
# =============================================================================

# Set authentication type
# AUTH_REMOTE_USER for header-based auth, AUTH_OAUTH for OIDC
AUTH_TYPE = AUTH_OAUTH

# Custom Security Manager Class
SECURITY_MANAGER_CLASS = AirflowOIDCSecurityManager

# =============================================================================
# OIDC Configuration  
# =============================================================================

# OIDC Client Configuration
OIDC_CLIENT_ID = os.environ.get('OIDC_CLIENT_ID', 'your-client-id')
OIDC_CLIENT_SECRET = os.environ.get('OIDC_CLIENT_SECRET', 'your-client-secret')
OIDC_DISCOVERY_URL = os.environ.get('OIDC_DISCOVERY_URL', 'https://your-ida-provider/.well-known/openid-configuration')

# OIDC Provider Details
OIDC_ISSUER = os.environ.get('OIDC_ISSUER', 'https://your-ida-provider')
OIDC_AUDIENCE = os.environ.get('OIDC_AUDIENCE', 'airflow')

# JWKS URL for token validation
OIDC_JWKS_URL = os.environ.get('OIDC_JWKS_URL', 'https://your-ida-provider/.well-known/jwks.json')

# =============================================================================
# IDA Specific Configuration
# =============================================================================

# IDA Authentication Configuration
I
"""
IDA Authentication Module for Airflow 2.10
Updated to work with modern Flask-AppBuilder and OIDC patterns
"""

import logging
import requests
import jwt
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
from urllib.parse import urljoin

from flask import current_app, session, request as flask_request
from flask_appbuilder.security.manager import BaseSecurityManager

log = logging.getLogger(__name__)


class IDAAuthError(Exception):
    """Custom exception for IDA authentication errors"""
    def __init__(self, message: str, error_code: str = None, status_code: int = None):
        self.message = message
        self.error_code = error_code
        self.status_code = status_code
        super().__init__(self.message)


class IDATokenValidator:
    """
    JWT Token validator for IDA authentication
    Handles token validation, refresh, and user info extraction
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.jwks_client = None
        self._init_jwks_client()
    
    def _init_jwks_client(self):
        """Initialize JWKS client for token validation"""
        try:
            from jose import jwk
            from jose.backends import RSAKey
            
            jwks_url = self.config.get('IDA_JWKS_URL')
            if jwks_url:
                # Fetch JWKS for token validation
                response = requests.get(jwks_url, timeout=10)
                response.raise_for_status()
                self.jwks_data = response.json()
                log.info("JWKS client initialized successfully")
        except Exception as e:
            log.warning(f"Failed to initialize JWKS client: {e}")
            self.jwks_data = None
    
    def validate_token(self, token: str) -> Dict[str, Any]:
        """
        Validate JWT token and extract claims
        
        Args:
            token: JWT token string
            
        Returns:
            Dict containing validated token claims
            
        Raises:
            IDAAuthError: If token validation fails
        """
        try:
            # Decode without verification first to get header
            unverified_header = jwt.get_unverified_header(token)
            unverified_payload = jwt.decode(token, options={"verify_signature": False})
            
            # Check token expiration
            exp = unverified_payload.get('exp')
            if exp and datetime.fromtimestamp(exp) < datetime.utcnow():
                raise IDAAuthError("Token has expired", "TOKEN_EXPIRED", 401)
            
            # Validate issuer
            expected_issuer = self.config.get('IDA_ISSUER')
            if expected_issuer and unverified_payload.get('iss') != expected_issuer:
                raise IDAAuthError("Invalid token issuer", "INVALID_ISSUER", 401)
            
            # Validate audience
            expected_audience = self.config.get('IDA_AUDIENCE')
            if expected_audience:
                aud = unverified_payload.get('aud')
                if isinstance(aud, list):
                    if expected_audience not in aud:
                        raise IDAAuthError("Invalid token audience", "INVALID_AUDIENCE", 401)
                elif aud != expected_audience:
                    raise IDAAuthError("Invalid token audience", "INVALID_AUDIENCE", 401)
            
            # If JWKS is available, verify signature
            if self.jwks_data:
                kid = unverified_header.get('kid')
                if not kid:
                    raise IDAAuthError("Token missing key ID", "MISSING_KID", 401)
                
                # Find the correct key
                signing_key = None
                for key in self.jwks_data.get('keys', []):
                    if key.get('kid') == kid:
                        signing_key = key
                        break
                
                if not signing_key:
                    raise IDAAuthError("Signing key not found", "KEY_NOT_FOUND", 401)
                
                # Verify signature (simplified - in production use proper JWKS library)
                try:
                    # This is a simplified version - use python-jose or similar for production
                    public_key = jwt.algorithms.RSAAlgorithm.from_jwk(signing_key)
                    payload = jwt.decode(
                        token,
                        public_key,
                        algorithms=['RS256'],
                        audience=expected_audience,
                        issuer=expected_issuer
                    )
                except jwt.InvalidTokenError as e:
                    raise IDAAuthError(f"Token signature validation failed: {e}", "INVALID_SIGNATURE", 401)
            else:
                # If no JWKS available, use unverified payload (not recommended for production)
                log.warning("Using unverified token - JWKS not available")
                payload = unverified_payload
            
            return payload
            
        except jwt.DecodeError as e:
            raise IDAAuthError(f"Token decode error: {e}", "DECODE_ERROR", 401)
        except Exception as e:
            if isinstance(e, IDAAuthError):
                raise
            raise IDAAuthError(f"Token validation error: {e}", "VALIDATION_ERROR", 500)
    
    def extract_user_info(self, token_payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract user information from validated token payload
        
        Args:
            token_payload: Validated JWT token payload
            
        Returns:
            Dict containing user information for Airflow
        """
        try:
            # Extract standard claims
            user_info = {
                'username': token_payload.get('preferred_username') or token_payload.get('sub'),
                'email': token_payload.get('email'),
                'first_name': token_payload.get('given_name', ''),
                'last_name': token_payload.get('family_name', ''),
                'full_name': token_payload.get('name', ''),
                'groups': token_payload.get('groups', []),
                'roles': token_payload.get('roles', []),
                'ida_user_id': token_payload.get('sub'),
                'token_exp': token_payload.get('exp'),
                'token_iat': token_payload.get('iat')
            }
            
            # Extract custom IDA claims
            ida_claims = token_payload.get('ida_claims', {})
            if ida_claims:
                user_info.update({
                    'department': ida_claims.get('department'),
                    'cost_center': ida_claims.get('cost_center'),
                    'manager': ida_claims.get('manager'),
                    'employee_id': ida_claims.get('employee_id')
                })
            
            # Determine Airflow role based on IDA groups/roles
            user_info['airflow_role'] = self._determine_airflow_role(
                user_info.get('groups', []),
                user_info.get('roles', [])
            )
            
            return user_info
            
        except Exception as e:
            log.error(f"Error extracting user info from token: {e}")
            raise IDAAuthError(f"Failed to extract user info: {e}", "USER_INFO_ERROR", 500)
    
    def _determine_airflow_role(self, groups: List[str], roles: List[str]) -> str:
        """
        Determine appropriate Airflow role based on IDA groups and roles
        
        Args:
            groups: List of user groups from IDA
            roles: List of user roles from IDA
            
        Returns:
            String representing the Airflow role
        """
        # Role mapping configuration
        role_mapping = self.config.get('IDA_ROLE_MAPPING', {
            'airflow-admin': 'Admin',
            'airflow-operator': 'Op',
            'airflow-viewer': 'Viewer',
            'airflow-user': 'User'
        })
        
        # Check groups first
        for group in groups:
            if group.lower() in role_mapping:
                return role_mapping[group.lower()]
        
        # Check roles 
        for role in roles:
            if role.lower() in role_mapping:
                return role_mapping[role.lower()]
        
        # Default role
        return self.config.get('IDA_DEFAULT_ROLE', 'Viewer')


class IDAAuth:
    """
    Main IDA Authentication class for Airflow 2.10
    Handles authentication flow, token management, and user synchronization
    """
    
    def __init__(self, app=None):
        self.app = app
        self.config = {}
        self.token_validator = None
        
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize IDA authentication with Flask app"""
        self.app = app
        
        # Load IDA configuration
        self.config = {
            'IDA_CLIENT_ID': app.config.get('IDA_CLIENT_ID'),
            'IDA_CLIENT_SECRET': app.config.get('IDA_CLIENT_SECRET'),
            'IDA_DISCOVERY_URL': app.config.get('IDA_DISCOVERY_URL'),
            'IDA_ISSUER': app.config.get('IDA_ISSUER'),
            'IDA_AUDIENCE': app.config.get('IDA_AUDIENCE'),
            'IDA_JWKS_URL': app.config.get('IDA_JWKS_URL'),
            'IDA_ROLE_MAPPING': app.config.get('IDA_ROLE_MAPPING', {}),
            'IDA_DEFAULT_ROLE': app.config.get('IDA_DEFAULT_ROLE', 'Viewer'),
            'IDA_TOKEN_REFRESH_THRESHOLD': app.config.get('IDA_TOKEN_REFRESH_THRESHOLD', 300),  # 5 minutes
            'IDA_USER_SYNC_ENABLED': app.config.get('IDA_USER_SYNC_ENABLED', True)
        }
        
        # Validate required configuration
        required_config = ['IDA_CLIENT_ID', 'IDA_CLIENT_SECRET', 'IDA_DISCOVERY_URL']
        missing_config = [key for key in required_config if not self.config.get(key)]
        
        if missing_config:
            raise ValueError(f"Missing required IDA configuration: {missing_config}")
        
        # Initialize token validator
        self.token_validator = IDATokenValidator(self.config)
        
        log.info("IDA authentication initialized successfully")
    
    def authenticate_user(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Authenticate user using IDA token
        
        Args:
            token: JWT token from IDA
            
        Returns:
            User information dict if authentication successful, None otherwise
        """
        try:
            # Validate token
            token_payload = self.token_validator.validate_token(token)
            
            # Extract user information
            user_info = self.token_validator.extract_user_info(token_payload)
            
            log.info(f"Successfully authenticated user: {user_info.get('username')}")
            return user_info
            
        except IDAAuthError as e:
            log.warning(f"IDA authentication failed: {e.message} (Code: {e.error_code})")
            return None
        except Exception as e:
            log.error(f"Unexpected error during IDA authentication: {e}")
            return None
    
    def get_user_from_request(self, request) -> Optional[Dict[str, Any]]:
        """
        Extract and authenticate user from HTTP request
        
        Args:
            request: Flask request object
            
        Returns:
            User information dict if found and valid, None otherwise
        """
        # Try to get token from Authorization header
        auth_header = request.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            token = auth_header[7:]  # Remove 'Bearer ' prefix
            return self.authenticate_user(token)
        
        # Try to get token from session
        session_token = session.get('ida_token')
        if session_token:
            return self.authenticate_user(session_token)
        
        # Try to get token from request parameters (for OIDC callback)
        token = request.args.get('access_token') or request.form.get('access_token')
        if token:
            return self.authenticate_user(token)
        
        return None
    
    def refresh_token_if_needed(self, user_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Refresh token if it's close to expiration
        
        Args:
            user_info: Current user information with token data
            
        Returns:
            Updated user info if token was refreshed, original user_info otherwise
        """
        try:
            token_exp = user_info.get('token_exp')
            if not token_exp:
                return user_info
            
            # Check if token needs refresh
            exp_time = datetime.fromtimestamp(token_exp)
            threshold = timedelta(seconds=self.config.get('IDA_TOKEN_REFRESH_THRESHOLD', 300))
            
            if exp_time - datetime.utcnow() < threshold:
                log.info(f"Token for user {user_info.get('username')} needs refresh")
                # Implement token refresh logic here if your IDA supports it
                # For now, just log and return original user info
                pass
            
            return user_info
            
        except Exception as e:
            log.error(f"Error checking token refresh: {e}")
            return user_info
    
    def sync_user_data(self, user_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Synchronize user data with IDA if enabled
        
        Args:
            user_info: Current user information
            
        Returns:
            Updated user information
        """
        if not self.config.get('IDA_USER_SYNC_ENABLED', True):
            return user_info
        
        try:
            # Implement user data synchronization logic here
            # This could involve calling IDA APIs to get updated user information
            log.debug(f"User data sync for {user_info.get('username')} - sync disabled or not implemented")
            return user_info
            
        except Exception as e:
            log.error(f"Error syncing user data: {e}")
            return user_info
    
    def logout_user(self, user_info: Dict[str, Any]) -> bool:
        """
        Handle user logout with IDA
        
        Args:
            user_info: User information for the user being logged out
            
        Returns:
            True if logout successful, False otherwise
        """
        try:
            # Clear session data
            session.pop('ida_token', None)
            session.pop('ida_user_info', None)
            
            # Implement IDA logout if your IDA supports it
            # This might involve calling an IDA logout endpoint
            
            log.info(f"User {user_info.get('username')} logged out successfully")
            return True
            
        except Exception as e:
            log.error(f"Error during logout: {e}")
            return False
        

        """
Updated Security Manager for Airflow 2.10 with OIDC Support
Compatible with Flask-AppBuilder 4.x and modern authentication patterns
"""

import logging
import jwt
from typing import Dict, Any, Optional, List
from urllib.parse import quote_plus, urlencode

from flask import redirect, request, session, url_for, flash
from flask_appbuilder.security.manager import BaseSecurityManager
from flask_appbuilder.security.views import AuthOIDView
from flask_appbuilder.models.sqla.interface import SQLAInterface
from flask_appbuilder import expose

from airflow.www.security import AirflowSecurityManager
from airflow.configuration import conf
from airflow.models import User

try:
    from authlib.integrations.flask_client import OAuth
    from authlib.common.errors import AuthlibBaseError
    HAS_AUTHLIB = True
except ImportError:
    HAS_AUTHLIB = False
    OAuth = None
    AuthlibBaseError = Exception

log = logging.getLogger(__name__)


class OIDCError(Exception):
    """Custom OIDC Error class for better error handling"""
    def __init__(self, message: str, error_code: str = None):
        self.message = message
        self.error_code = error_code
        super().__init__(self.message)


class OpenIDConnect2:
    """
    Modern OpenID Connect client implementation using Authlib
    Replaces the deprecated flask-oidc library
    """
    
    def __init__(self, app=None):
        self.app = app
        self.oauth = None
        self.client = None
        
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize the OIDC client with Flask app"""
        if not HAS_AUTHLIB:
            raise ImportError("authlib is required for OIDC authentication")
            
        self.app = app
        self.oauth = OAuth(app)
        
        # Configure OIDC client
        self.client = self.oauth.register(
            name='oidc',
            client_id=app.config.get('OIDC_CLIENT_ID'),
            client_secret=app.config.get('OIDC_CLIENT_SECRET'),
            server_metadata_url=app.config.get('OIDC_DISCOVERY_URL'),
            client_kwargs={
                'scope': 'openid email profile',
                'code_challenge_method': 'S256'  # PKCE support
            }
        )
    
    def authenticate(self, redirect_uri: str = None) -> str:
        """Initiate OIDC authentication flow"""
        if not redirect_uri:
            redirect_uri = url_for('AuthOIDCView.oauth_authorized', _external=True)
        
        return self.client.authorize_redirect(redirect_uri)
    
    def get_userinfo(self, token: Dict[str, Any]) -> Dict[str, Any]:
        """Get user information from OIDC provider"""
        try:
            userinfo = self.client.parse_id_token(token)
            return userinfo
        except AuthlibBaseError as e:
            log.error(f"Failed to get userinfo: {e}")
            raise OIDCError(f"Failed to get user information: {e}")


class OIDCSecurityManagerMixin:
    """
    Mixin class that provides OIDC functionality to security managers
    """
    
    def __init__(self):
        super().__init__()
        self.oidc = None
        self._init_oidc()
    
    def _init_oidc(self):
        """Initialize OIDC client"""
        if self.appbuilder and self.appbuilder.app:
            self.oidc = OpenIDConnect2(self.appbuilder.app)
    
    def get_oauth_user_info(self, provider: str, resp: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract user information from OAuth response
        Compatible with Flask-AppBuilder 4.x oauth_user_info_getter decorator
        """
        if provider.lower() == 'oidc':
            try:
                token = resp.get('access_token') or resp
                userinfo = self.oidc.get_userinfo(token)
                
                # Map OIDC claims to Airflow user fields
                user_info = {
                    'username': userinfo.get('preferred_username') or userinfo.get('email'),
                    'email': userinfo.get('email'),
                    'first_name': userinfo.get('given_name', ''),
                    'last_name': userinfo.get('family_name', ''),
                    'role': self._map_oidc_roles(userinfo.get('roles', []))
                }
                
                return user_info
                
            except Exception as e:
                log.error(f"Error extracting OAuth user info: {e}")
                raise OIDCError(f"Failed to extract user info: {e}")
        
        return {}
    
    def _map_oidc_roles(self, oidc_roles: List[str]) -> str:
        """
        Map OIDC roles to Airflow roles
        Override this method to customize role mapping
        """
        role_mapping = self.appbuilder.app.config.get('AUTH_ROLES_MAPPING', {})
        
        # Default role mapping
        default_mapping = {
            'admin': 'Admin',
            'operator': 'Op', 
            'viewer': 'Viewer',
            'user': 'User',
            'public': 'Public'
        }
        
        role_mapping.update(default_mapping)
        
        # Find the highest privilege role
        for oidc_role in oidc_roles:
            if oidc_role.lower() in role_mapping:
                return role_mapping[oidc_role.lower()]
        
        # Default role if no mapping found
        return self.appbuilder.app.config.get('AUTH_USER_REGISTRATION_ROLE', 'Viewer')


class AuthOIDCView(AuthOIDView):
    """
    Custom OIDC Authentication View for Airflow 2.10
    Updated to work with modern Flask-AppBuilder patterns
    """
    
    @expose('/oauth-authorized')
    def oauth_authorized(self):
        """Handle OAuth callback from OIDC provider"""
        try:
            # Get the authorization response
            token = self.appbuilder.sm.oauth.oidc.authorize_access_token()
            
            if not token:
                flash('Access denied by OIDC provider', 'error')
                return redirect(url_for('AuthDBView.login'))
            
            # Get user info from token
            user_info = self.appbuilder.sm.get_oauth_user_info('oidc', token)
            
            if not user_info or not user_info.get('email'):
                flash('Unable to get user information from OIDC provider', 'error')
                return redirect(url_for('AuthDBView.login'))
            
            # Authenticate or create user
            user = self.appbuilder.sm.auth_user_oauth(user_info)
            
            if user:
                self.appbuilder.sm.login_user(user, remember=False)
                return redirect(self.appbuilder.get_url_for_index)
            else:
                flash('Authentication failed', 'error')
                return redirect(url_for('AuthDBView.login'))
                
        except Exception as e:
            log.error(f"OAuth authorization error: {e}")
            flash(f'Authentication error: {str(e)}', 'error')
            return redirect(url_for('AuthDBView.login'))


class AirflowOIDCSecurityManager(OIDCSecurityManagerMixin, AirflowSecurityManager):
    """
    Enhanced Airflow Security Manager with OIDC support for version 2.10
    
    This class combines:
    - Modern OIDC authentication using Authlib
    - Airflow 2.10 compatibility
    - Enhanced security features
    - Proper role mapping and user management
    """
    
    # Custom auth view for OIDC
    authoidview = AuthOIDCView
    
    def __init__(self, appbuilder):
        super().__init__(appbuilder)
        
        # Initialize OAuth providers
        self.oauth_providers = []
        if self.appbuilder.app.config.get('OIDC_CLIENT_ID'):
            self.oauth_providers.append({
                'name': 'oidc',
                'icon': 'fa-openid',
                'token_key': 'access_token',
                'remote_app': self.oidc.client if hasattr(self, 'oidc') else None
            })
    
    @property
    def oauth_user_info_getter(self):
        """
        Decorator for OAuth user info getter methods
        Compatible with Flask-AppBuilder 4.x
        """
        def decorator(f):
            def wrapper(*args, **kwargs):
                return f(*args, **kwargs)
            return wrapper
        return decorator
    
    def auth_user_oauth(self, userinfo: Dict[str, Any]) -> Optional[User]:
        """
        Authenticate user via OAuth/OIDC
        Updated for Airflow 2.10 compatibility
        """
        try:
            username = userinfo.get('username')
            email = userinfo.get('email')
            
            if not username or not email:
                log.warning("Missing username or email in userinfo")
                return None
            
            # Find existing user
            user = self.find_user(username=username)
            
            if not user:
                user = self.find_user(email=email)
            
            # Create new user if not found
            if not user:
                user = self.add_user(
                    username=username,
                    first_name=userinfo.get('first_name', ''),
                    last_name=userinfo.get('last_name', ''),
                    email=email,
                    role=self.find_role(userinfo.get('role', 'Viewer'))
                )
                
                if user:
                    log.info(f"Created new user via OIDC: {username}")
                else:
                    log.error(f"Failed to create user: {username}")
                    return None
            else:
                # Update existing user info
                user.first_name = userinfo.get('first_name', user.first_name)
                user.last_name = userinfo.get('last_name', user.last_name)
                user.email = email
                
                # Update role if changed
                new_role = self.find_role(userinfo.get('role', 'Viewer'))
                if new_role and user.roles != [new_role]:
                    user.roles = [new_role]
                
                self.get_session.commit()
                log.info(f"Updated existing user via OIDC: {username}")
            
            return user
            
        except Exception as e:
            log.error(f"Error in auth_user_oauth: {e}")
            return None
    
    def get_user_menu_access(self, menu_names: List[str] = None) -> List[str]:
        """
        Get menu access for current user
        Updated for Airflow 2.10 permission model
        """
        if not menu_names:
            return []
        
        user_menu_access = []
        user = self.get_user_by_id(self.get_user_id())
        
        if user and user.roles:
            for role in user.roles:
                for permission in role.permissions:
                    # Handle new DAG permission format (DAG:dag_id)
                    if permission.resource and permission.resource.name in menu_names:
                        if permission.resource.name not in user_menu_access:
                            user_menu_access.append(permission.resource.name)
        
        return user_menu_access
    
    def has_access(self, permission_name: str, resource_name: str) -> bool:
        """
        Check if current user has access to a resource
        Updated to handle new permission model in Airflow 2.10
        """
        # Handle legacy DAG permissions
        if permission_name in ['can_dag_read', 'can_dag_edit']:
            # Map to new permission format
            new_permission = 'can_read' if permission_name == 'can_dag_read' else 'can_edit'
            new_resource = f"DAG:{resource_name}" if not resource_name.startswith('DAG:') else resource_name
            return super().has_access(new_permission, new_resource)
        
        return super().has_access(permission_name, resource_name)
    
    'll help you understand the changes needed to migrate your Airflow authentication setup from version 2.3.2 to 2.10. Let me search for the latest information on Airflow 2.10 authentication changes.Airflow 2.10 authentication changes migration guide10 resultsUpgrading from 1.10 to 2 — Airflow Documentationapache.orgMigration guide for Airflow 2.0 · Issue #10089 · apache/airflowgithub.comApache Airflow 1.x to 2.x - migrationlinkedin.comAirflow 2 to 3 auto migration rules · Issue #41641 · apache/airflowgithub.comUpgrading to Airflow 3 — Airflow 3.0.3 Documentationapache.orgUpgrade from Apache Airflow® 2 to 3 | Astronomer Documentationastronomer.ioTransitioning from Airflow 1 to 2 - NashTech Blognashtechglobal.comUpgrading to Airflow 2.0. We ran into a couple of gotchas during… | by Sterling Jackson | Mediummedium.comUpgrading to Apache Airflow 2airflowsummit.orgHow to upgrade to Airflow 2.0? - Stack Overflowstackoverflow.comLet me search for more specific information about Airflow 2.10 authentication and security manager changes.Airflow 2.10 security manager OIDC authentication breaking changes10 resultsThird Party OIDC Authentication with Airflow 2.xrearc.ioSecurity :: airflow :: Stackable Documentationstackable.techAccess is denied alert after successful login using OIDC · apache/airflow · Discussion #21358github.comSupport for general OIDC providers or making it clear in document · Issue #35131 · apache/airflowgithub.comVulnerability in long deprecated OpenID authentication method in Flask AppBuilder | Apache Airflowapache.orgFAB auth manager authentication — apache-airflow-providers-fab Documentationapache.orgLOGIN does not work after upgrading to Airflow 2.7.3 "ERROR - Error returning OAuth user info: 'id_token'" · apache/airflow · Discussion #35939github.comThird Party OIDC Authentication with Airflow 2.x | Rearc - Engineering Blogrearc.ioSecurity — Airflow Documentationapache.orgRelease Notes — Airflow 3.0.3 Documentationapache.orgBased on the search results and your current Airflow 2.3.2 setup, I can provide you with the key changes needed for migrating to Airflow 2.10. Here are the major changes and migration steps:
Key Changes from Airflow 2.3.2 to 2.10
1. Auth Backend Configuration Changes
Current (2.3.2):
auth_backend = airflow.api.auth.backend.default
AIRFLOW__WEBSERVER__AUTH__BACKEND=cibdaos_xxxxx_airflow_ida.fab.security.AirflowOIDSecurityManager

or 2.10:

The auth backend configuration structure remains largely the same, but you'll need to ensure your custom security manager is compatible with the newer Flask-AppBuilder version
There was a vulnerability fix in the OpenID authentication method in Flask AppBuilder, with users advised to upgrade to Apache Airflow 2.8.2 Vulnerability in long deprecated OpenID authentication method in Flask AppBuilder | Apache Airflow

2. Security Manager Changes
Your current classes need updates:
Required Updates:

IDAAuth class in ida.py
OpenIDEConnect2, oidc_error, OIDCSecurityManagerMixin in security.py
AirflowOIDCSecurityManager class
    
    Key Changes Needed:

Flask-AppBuilder Compatibility: Ensure your custom security manager inherits from the correct base classes for the newer Flask-AppBuilder version
OIDC Implementation: Flask-OIDC should be marked as abandoned and isn't supported by airflow Access is denied alert after successful login using OIDC · apache/airflow · Discussion #21358, so you may need to migrate to a different OIDC implementation
Permission Model: The DAG-level permission actions, can_dag_read and can_dag_edit are deprecated. They are being replaced with can_read and can_edit, with resource names prefixed with DAG: Upgrading from 1.10 to 2 — Airflow Documentation

3. Configuration Updates
webserver_config.py changes:

. Security Manager Changes
Your current classes need updates:
Required Updates:

IDAAuth class in ida.py
OpenIDEConnect2, oidc_error, OIDCSecurityManagerMixin in security.py
AirflowOIDCSecurityManager class

Key Changes Needed:

Flask-AppBuilder Compatibility: Ensure your custom security manager inherits from the correct base classes for the newer Flask-AppBuilder version
OIDC Implementation: Flask-OIDC should be marked as abandoned and isn't supported by airflow Access is denied alert after successful login using OIDC · apache/airflow · Discussion #21358, so you may need to migrate to a different OIDC implementation
Permission Model: The DAG-level permission actions, can_dag_read and can_dag_edit are deprecated. They are being replaced with can_read and can_edit, with resource names prefixed with DAG: Upgrading from 1.10 to 2 — Airflow Documentation

3. Configuration Updates
webserver_config.py changes:

# Current
AUTH_TYPE = AUTH_REMOTE_USER
SECURITY_MANAGER_CLASS = AirflowOIDCSecurityManager

# For 2.10 - likely similar but verify compatibility
AUTH_TYPE = AUTH_REMOTE_USER  # May need adjustment
SECURITY_MANAGER_CLASS = YourUpdatedAirflowOIDCSecurityManager



python# Current
AUTH_TYPE = AUTH_REMOTE_USER
SECURITY_MANAGER_CLASS = AirflowOIDCSecurityManager

# For 2.10 - likely similar but verify compatibility
AUTH_TYPE = AUTH_REMOTE_USER  # May need adjustment
SECURITY_MANAGER_CLASS = YourUpdatedAirflowOIDCSecurityManager
4. Role Management
Your current roles (Admin, Op, Public, User, Viewer) should still work, but verify:

Permission mappings for DAG-level access
Role hierarchy and inheritance

5. Required Package Updates
Since you mentioned packages, you'll likely need to update:
bash# Core dependencies that may need updates
pip install apache-airflow==2.10.x
pip install Flask-AppBuilder>=4.x.x  # Check latest compatible version
pip install authlib  # If using OIDC
pip install python-jose[cryptography]  # For JWT handling


Migration Steps

Test Environment Setup: Create a test environment with Airflow 2.10
Update Custom Classes: Modify your ida.py and security.py files to be compatible with newer Flask-AppBuilder
Configuration Migration: Update your webserver_config.py and environment variables
Database Migration: Run airflow db migrate after the upgrade
Permission Verification: Check that all roles and permissions work correctly
OIDC Flow Testing: Thoroughly test the authentication flow

Immediate Action Items

Review Your OIDC Implementation: Given that Flask-OIDC is no longer recommended, consider migrating to a more modern OIDC solution
Update Permission Checks: Replace any can_dag_read/can_dag_edit with the new can_read/can_edit format
Test Flask-AppBuilder Compatibility: Ensure your custom security manager classes work with the newer Flask-AppBuilder version used in Airflow 2.10

Would you like me to help you create updated versions of your custom security manager classes, or do you need more specific guidance on any of these migration steps?


==============================
chatgpt

✅ 1️⃣ FAB version is newer & stricter
	•	Airflow 2.10 uses a newer Flask AppBuilder version.
	•	Your custom AirflowOIDCSecurityManager must correctly inherit AirflowSecurityManager, not the old FAB one directly.
	•	The auth_user_remote_user() override must call super() correctly.


Auth backend must match

In Airflow 2.10, the webserver respects:
[webserver]
auth_backend = cibdaos_xxxx_airflow_ida.fab.security.AirflowOIDCSecurityManager

or the EnvironmentError

AIRFLOW__WEBSERVER__AUTH__BACKEND=cibdaos_xxxx_airflow_ida.fab.security.AirflowOIDCSecurityManager
So you MUST ensure your upgraded image sets this var OR your Helm values.yaml sets it.

webserver_config.py must be loaded

Don’t lose this!
Your webserver_config.py must be mounted or baked in your Docker image:
docker file :

COPY webserver_config.py ${AIRFLOW_HOME}/webserver_config.py

Or mount it with a ConfigMap if you deploy with Helm.

ookies: SameSite & Secure

Newer Flask AppBuilder versions enforce stricter cookie behavior.
Problem: If your OIDC flow jumps domains (blue/green) → the auth cookie may not be sent.

fix: Add this to webserver_config.py:
SESSION_COOKIE_SAMESITE = "None"
SESSION_COOKIE_SECURE = True

Check your custom Security Manager

Your AirflowOIDCSecurityManager must look like:
from airflow.www.security import AirflowSecurityManager

class AirflowOIDCSecurityManager(
    OIDCSecurityManagerMixin,
    OpenIDEConnect2,
    AirflowSecurityManager
):
    def auth_user_remote_user(self, username):
        # ✅ MUST call super() or recreate user object properly
        user = super().auth_user_remote_user(username)
        # ✅ Your extra mapping logic here
        return user
    

If you skip super(), Airflow may fail to create the session.


API auth stays the same

✅ auth_backend = airflow.api.auth.backend.default → no change needed for the REST API if you still use it for token auth.

⸻

✅ 7️⃣ Roles must exist

Run this after upgrade:

airflow db upgrade
airflow roles list

Confirm Op and Viewer still exist — and your custom auth_user_remote_user() must still map the correct roles.

⸻

✅ 8️⃣ DB upgrade is required

Newer Airflow versions add permission names → if you skip airflow db upgrade, your RBAC check will fail.
airflow db upgrade

eployment image: required files

Your Dockerfile must:

COPY cibdaos_xxxx_airflow_ida/ /opt/airflow/plugins/cibdaos_xxxx_airflow_ida/
COPY webserver_config.py ${AIRFLOW_HOME}/webserver_config.py

If you package ida.py + security.py as a wheel → run pip install your_oidc_package.whl.

✅ If you RUN -y install via OS deps → make sure Python sees your custom module in PYTHONPATH.

⸻

✅📌 Minimal webserver_config.py for 2.10

Here’s what yours should look like:


from flask_appbuilder.security.manager import AUTH_REMOTE_USER

AUTH_TYPE = AUTH_REMOTE_USER
SECURITY_MANAGER_CLASS = "cibdaos_xxxx_airflow_ida.fab.security.AirflowOIDCSecurityManager"

SESSION_COOKIE_SAMESITE = "None"
SESSION_COOKIE_SECURE = True

Debug: Is your custom auth running?import logging
log = logging.getLogger(__name__)

class AirflowOIDCSecurityManager(...):
    def auth_user_remote_user(self, username):
        log.info(f"REMOTE_USER from header: {username}")
        ..

Add logging inside AirflowOIDCSecurityManager:

kubectl logs <webserver-pod>
Checklist for your upgrade

Step
✅
Keep your auth_backend for API
✅
Keep your OIDC SECURITY_MANAGER_CLASS for UI
✅
Inherit AirflowSecurityManager in your custom class
✅
Keep AUTH_TYPE = AUTH_REMOTE_USER
✅
Add SESSION_COOKIE_SAMESITE = "None" if you need cross-domain
✅
Ensure webserver_config.py is mounted
✅
Run airflow db upgrade
✅
Test roles list — make sure your OIDC flow maps valid roles
✅
Add logs to confirm auth_user_remote_user is running
✅
Build Docker image with COPY for all custom files



Below is a realistic template for how your ida.py should look in Airflow 2.10, based on your OIDC + Remote User flow.
I’ll include modern patterns that work with the newer Flask AppBuilder (FAB) version that Airflow 2.10 uses.

Goal

You want your ida.py to:
	•	Wire your custom AirflowOIDCSecurityManager to Airflow.
	•	Use an OIDC helper class (IDAAuth) to do token checks.
	•	Plug into Remote-User header flow (AUTH_REMOTE_USER).
	•	Be cleanly importable: cibdaos_xxxx_airflow_ida.fab.security.AirflowOIDCSecurityManager.

⸻

Below is an example ida.py you can adapt.
This assumes:
	•	You already have security.py for mixins.
	•	Your webserver_config.py sets AUTH_TYPE and SECURITY_MANAGER_CLASS.



"""
ida.py -- Custom OIDC auth glue for Airflow 2.10
Path: cibdaos_xxxx_airflow_ida/fab/ida.py
"""

from airflow.www.security import AirflowSecurityManager  # Always use the Airflow one, not plain FAB
from flask import request, redirect, session
from flask_appbuilder.security.manager import AUTH_REMOTE_USER
import logging

from cibdaos_xxxx_airflow_ida.fab.security import (
    OIDCSecurityManagerMixin,
    OpenIDEConnect2
)

log = logging.getLogger(__name__)

class IDAAuth:
    """
    Helper class to handle your OIDC / JWT / Remote User logic.
    """

    def __init__(self):
        pass  # Add any setup if needed

    def get_remote_user(self):
        """
        Extract the Remote-User header or OIDC claim.
        """
        remote_user = request.headers.get("REMOTE_USER")
        log.info(f"IDAAuth: REMOTE_USER header value: {remote_user}")
        return remote_user

    def validate_token(self, token):
        """
        If you also use bearer tokens, validate them here.
        """
        # Example stub, replace with real call
        if token == "valid_token":
            return True
        return False


class AirflowOIDCSecurityManager(
    OIDCSecurityManagerMixin,  # your mixin for OIDC helpers
    OpenIDEConnect2,           # any custom connect logic
    AirflowSecurityManager     # must extend AirflowSecurityManager!
):
    """
    Main custom security manager for Airflow 2.10 OIDC + Remote User flow.
    """

    auth_type = AUTH_REMOTE_USER

    def __init__(self, appbuilder):
        super().__init__(appbuilder)
        self.ida_auth = IDAAuth()  # initialize your helper

    def auth_user_remote_user(self, username):
        """
        Override the Remote-User auth flow.
        Called when Airflow sees REMOTE_USER.
        """
        log.info(f"AirflowOIDCSecurityManager: Received remote user: {username}")

        # Call super to get or create the user object
        user = super().auth_user_remote_user(username)

        # You could add extra checks here:
        # Example: check token, roles, claims, or your own API.
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if token and not self.ida_auth.validate_token(token):
            log.warning(f"AirflowOIDCSecurityManager: Invalid token for user {username}")
            return None

        # Example: force user to always have a certain role if needed
        if user:
            if not user.roles:
                viewer_role = self.find_role("Viewer")
                user.roles.append(viewer_role)
                self.update_user(user)

        return user

    def get_url_for_login(self):
        """
        Optional: if you want to redirect to your OIDC provider.
        """
        log.info("Redirecting to custom OIDC login page...")
        return "/oidc/login"
    
    ey points in this template

✔️ Uses AirflowSecurityManager as the base — required for Airflow 2.10 RBAC.
✔️ The IDAAuth helper extracts REMOTE_USER or validates a bearer token if needed.
✔️ auth_user_remote_user():
	•	Pulls the REMOTE_USER header.
	•	Validates your custom token if used.
	•	Calls super() to reuse the core Airflow user creation logic.
	•	Ensures the user has a fallback role if needed.
✔️ Shows how to override the get_url_for_login() if you want to force a redirect to an OIDC login page.

⸻

✅ ✅ ✅ What else you need

In webserver_config.py:
from flask_appbuilder.security.manager import AUTH_REMOTE_USER

AUTH_TYPE = AUTH_REMOTE_USER
SECURITY_MANAGER_CLASS = "cibdaos_xxxxx" \_airflow_ida.fab.ida.AirflowOIDCSecurityManager"

SESSION_COOKIE_SAMESITE = "None"
SESSION_COOKIE_SECURE = True

docker file :
# Example for Docker build
COPY cibdaos_xxxx_airflow_ida/ /opt/airflow/plugins/cibdaos_xxxx_airflow_ida/
COPY webserver_config.py ${AIRFLOW_HOME}/webserver_config.py

In airflow.cfg or env vars:

export AIRFLOW__WEBSERVER__AUTH_BACKEND=cibdaos_xxxx_airflow_ida.fab.ida.AirflowOIDCSecurityManager

When you test
	•	Check logs: kubectl logs <webserver> should show your log lines.
	•	Confirm REMOTE_USER header is passed correctly by your LB/Ingress.
	•	Confirm roles exist: airflow roles list.
	•	Confirm airflow db upgrade runs cleanly.


Done!

This modern ida.py gives you:
	•	✅ OIDC + Remote-User header flow.
	•	✅ Good super() inheritance.
	•	✅ Version-safe for Airflow 2.10 + newer FAB.
	•	✅ Clean logging to debug.

