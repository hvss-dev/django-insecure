"""Configurações de produção para o projeto Django.

Este arquivo contém configurações específicas para ambiente de produção,
com foco em segurança e performance.
"""

from .settings import *
from .env_validation import get_env_variable, get_bool_env, get_list_env

# =============================================================================
# CONFIGURAÇÕES DE SEGURANÇA PARA PRODUÇÃO
# =============================================================================

# Debug DEVE ser False em produção
DEBUG = False

# Hosts permitidos devem ser específicos
ALLOWED_HOSTS = get_list_env('DJANGO_ALLOWED_HOSTS', [])

# Configurações de segurança HTTPS
SECURE_SSL_REDIRECT = get_bool_env('SECURE_SSL_REDIRECT', True)
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
SECURE_HSTS_SECONDS = 31536000  # 1 ano
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_BROWSER_XSS_FILTER = True
X_FRAME_OPTIONS = 'DENY'

# Configurações de cookies seguros
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Strict'
CSRF_COOKIE_SAMESITE = 'Strict'

# =============================================================================
# CONFIGURAÇÕES DE BANCO DE DADOS
# =============================================================================

# Para produção, use PostgreSQL ou MySQL
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': get_env_variable('DB_NAME'),
        'USER': get_env_variable('DB_USER'),
        'PASSWORD': get_env_variable('DB_PASSWORD'),
        'HOST': get_env_variable('DB_HOST', 'localhost'),
        'PORT': get_env_variable('DB_PORT', '5432'),
        'OPTIONS': {
            'sslmode': 'require',
        },
    }
}

# =============================================================================
# CONFIGURAÇÕES DE LOGGING
# =============================================================================

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
        'simple': {
            'format': '{levelname} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'file': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': get_env_variable('LOG_FILE', '/var/log/django/security.log'),
            'formatter': 'verbose',
        },
        'security_file': {
            'level': 'WARNING',
            'class': 'logging.FileHandler',
            'filename': get_env_variable('SECURITY_LOG_FILE', '/var/log/django/security_alerts.log'),
            'formatter': 'verbose',
        },
        'console': {
            'level': 'ERROR',
            'class': 'logging.StreamHandler',
            'formatter': 'simple',
        },
    },
    'loggers': {
        'django': {
            'handlers': ['file', 'console'],
            'level': get_env_variable('LOG_LEVEL', 'INFO'),
            'propagate': True,
        },
        'django.security': {
            'handlers': ['security_file', 'console'],
            'level': 'WARNING',
            'propagate': False,
        },
        'security': {
            'handlers': ['security_file', 'console'],
            'level': 'INFO',
            'propagate': False,
        },
    },
}

# =============================================================================
# CONFIGURAÇÕES DE CACHE
# =============================================================================

CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.redis.RedisCache',
        'LOCATION': get_env_variable('REDIS_URL', 'redis://127.0.0.1:6379/1'),
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
        },
        'KEY_PREFIX': 'django_security',
        'TIMEOUT': 300,
    }
}

# =============================================================================
# CONFIGURAÇÕES DE EMAIL
# =============================================================================

EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = get_env_variable('EMAIL_HOST')
EMAIL_PORT = int(get_env_variable('EMAIL_PORT', '587'))
EMAIL_USE_TLS = get_bool_env('EMAIL_USE_TLS', True)
EMAIL_HOST_USER = get_env_variable('EMAIL_HOST_USER')
EMAIL_HOST_PASSWORD = get_env_variable('EMAIL_HOST_PASSWORD')
DEFAULT_FROM_EMAIL = get_env_variable('DEFAULT_FROM_EMAIL')

# =============================================================================
# CONFIGURAÇÕES DE ARQUIVOS ESTÁTICOS E MEDIA
# =============================================================================

STATIC_ROOT = get_env_variable('STATIC_ROOT', '/var/www/static/')
MEDIA_ROOT = get_env_variable('MEDIA_ROOT', '/var/www/media/')

# Configurações de segurança para upload de arquivos
FILE_UPLOAD_MAX_MEMORY_SIZE = 5242880  # 5MB
DATA_UPLOAD_MAX_MEMORY_SIZE = 5242880  # 5MB
FILE_UPLOAD_PERMISSIONS = 0o644

# =============================================================================
# CONFIGURAÇÕES DE MIDDLEWARE DE SEGURANÇA
# =============================================================================

# Adicionar middleware de segurança no início
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
] + MIDDLEWARE

# =============================================================================
# CONFIGURAÇÕES ADICIONAIS DE SEGURANÇA
# =============================================================================

# Configurações de senha
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
        'OPTIONS': {
            'min_length': 12,
        }
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Timeout de sessão (30 minutos)
SESSION_COOKIE_AGE = 1800
SESSION_EXPIRE_AT_BROWSER_CLOSE = True

# Configurações de CORS (se necessário)
# CORS_ALLOWED_ORIGINS = get_list_env('CORS_ALLOWED_ORIGINS', [])
# CORS_ALLOW_CREDENTIALS = True

# Rate limiting (se usando django-ratelimit)
# RATELIMIT_ENABLE = True
# RATELIMIT_USE_CACHE = 'default'