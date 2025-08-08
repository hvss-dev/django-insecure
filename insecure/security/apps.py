"""
Configuração da aplicação Security.

Este módulo contém a configuração da aplicação Django
responsável pelas demonstrações de segurança.
"""
from django.apps import AppConfig


class SecurityConfig(AppConfig):
    """
    Configuração da aplicação Security.
    
    Esta classe configura a aplicação Django que demonstra
    vulnerabilidades de segurança e suas correções.
    """
    name = 'security'
    verbose_name = 'Demonstrações de Segurança'
    default_auto_field = 'django.db.models.BigAutoField'
