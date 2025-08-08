"""
Validação de variáveis de ambiente para configurações seguras.

Este módulo fornece funções para validar e obter variáveis
de ambiente de forma segura, com fallbacks apropriados.
"""
import os
from django.core.exceptions import ImproperlyConfigured


def get_env_variable(var_name, default=None, required=False):
    """
    Obtém variável de ambiente com validação.
    
    Args:
        var_name (str): Nome da variável de ambiente
        default: Valor padrão se a variável não existir
        required (bool): Se True, levanta exceção se não encontrar
        
    Returns:
        str: Valor da variável de ambiente
        
    Raises:
        ImproperlyConfigured: Se variável obrigatória não for encontrada
    """
    try:
        return os.environ[var_name]
    except KeyError:
        if required:
            error_msg = f"Set the {var_name} environment variable"
            raise ImproperlyConfigured(error_msg)
        return default


def get_bool_env(var_name, default=False):
    """
    Obtém variável de ambiente como boolean.
    
    Args:
        var_name (str): Nome da variável de ambiente
        default (bool): Valor padrão
        
    Returns:
        bool: Valor convertido para boolean
    """
    value = get_env_variable(var_name, str(default))
    return value.lower() in ('true', '1', 'yes', 'on')


def get_list_env(var_name, default=None, separator=','):
    """
    Obtém variável de ambiente como lista.
    
    Args:
        var_name (str): Nome da variável de ambiente
        default (list): Lista padrão
        separator (str): Separador para split
        
    Returns:
        list: Lista de valores
    """
    if default is None:
        default = []
    
    value = get_env_variable(var_name)
    if value is None:
        return default
    
    return [item.strip() for item in value.split(separator) if item.strip()]


def validate_secret_key(secret_key):
    """
    Valida se a SECRET_KEY é segura.
    
    Args:
        secret_key (str): Chave secreta para validar
        
    Raises:
        ImproperlyConfigured: Se a chave não for segura
    """
    if not secret_key:
        raise ImproperlyConfigured("SECRET_KEY cannot be empty")
    
    if len(secret_key) < 50:
        raise ImproperlyConfigured("SECRET_KEY must be at least 50 characters long")
    
    # Verificar se não é uma chave de desenvolvimento conhecida
    insecure_keys = [
        'dev-key-change-in-production',
        'django-insecure-',
        'your-secret-key-here'
    ]
    
    for insecure_key in insecure_keys:
        if insecure_key in secret_key:
            raise ImproperlyConfigured(
                f"SECRET_KEY appears to be insecure. "
                f"Do not use development keys in production."
            )