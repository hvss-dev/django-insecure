"""Configurações de teste para o projeto Django.

Este arquivo contém configurações específicas para execução de testes,
com validações relaxadas para facilitar os testes automatizados.
"""

import os
from pathlib import Path

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# Application definition
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'security',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'insecure.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'insecure.wsgi.application'

# Internationalization
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_L10N = True
USE_TZ = True

# Static files (CSS, JavaScript, Images)
STATIC_URL = '/static/'

# Default primary key field type
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# =============================================================================
# CONFIGURAÇÕES BÁSICAS PARA TESTES
# =============================================================================

# Secret key para testes (não precisa ser segura)
SECRET_KEY = 'test-secret-key-for-automated-testing-only-not-for-production-use'

# Debug pode ser True em testes
DEBUG = True

# Hosts permitidos para testes
ALLOWED_HOSTS = ['localhost', '127.0.0.1', 'testserver']

# =============================================================================
# CONFIGURAÇÕES DE BANCO DE DADOS PARA TESTES
# =============================================================================

# Usar SQLite em memória para testes rápidos
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': ':memory:',
    }
}

# =============================================================================
# CONFIGURAÇÕES DE CACHE PARA TESTES
# =============================================================================

# Cache local para testes
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
    }
}

# =============================================================================
# CONFIGURAÇÕES DE EMAIL PARA TESTES
# =============================================================================

# Email backend para testes
EMAIL_BACKEND = 'django.core.mail.backends.locmem.EmailBackend'

# =============================================================================
# CONFIGURAÇÕES DE ARQUIVOS PARA TESTES
# =============================================================================

# Diretório temporário para testes
import tempfile
TEST_TEMP_DIR = tempfile.mkdtemp()
SAFE_FILES_DIR = TEST_TEMP_DIR

# =============================================================================
# CONFIGURAÇÕES DE LOGGING PARA TESTES
# =============================================================================

# Logging simplificado para testes
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
        },
    },
    'loggers': {
        'django': {
            'handlers': ['console'],
            'level': 'WARNING',
        },
        'security': {
            'handlers': ['console'],
            'level': 'INFO',
        },
    },
}

# =============================================================================
# CONFIGURAÇÕES DE SEGURANÇA RELAXADAS PARA TESTES
# =============================================================================

# Desabilitar algumas validações de segurança em testes
SECURE_SSL_REDIRECT = False
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False

# =============================================================================
# CONFIGURAÇÕES DE PERFORMANCE PARA TESTES
# =============================================================================

# Acelerar testes desabilitando algumas funcionalidades
PASSWORD_HASHERS = [
    'django.contrib.auth.hashers.MD5PasswordHasher',
]

# Desabilitar migrações para acelerar testes
class DisableMigrations:
    def __contains__(self, item):
        return True
    
    def __getitem__(self, item):
        return None

MIGRATION_MODULES = DisableMigrations()