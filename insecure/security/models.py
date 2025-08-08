"""
Modelo de usuário para demonstração de segurança.

Este módulo contém o modelo User usado nas demonstrações
de vulnerabilidades de segurança corrigidas.
"""
from django.db import models


class User(models.Model):
    """
    Modelo de usuário simples para testes de segurança.
    
    Este modelo é usado para demonstrar correções de vulnerabilidades
    como SQL injection e validação de entrada.
    
    Attributes:
        id (int): Identificador único do usuário (chave primária)
        name (str): Nome do usuário (máximo 200 caracteres)
    """
    id = models.IntegerField(primary_key=True)
    name = models.CharField(max_length=200)

    def __str__(self):
        """Representação string do usuário."""
        return f'User {self.id} {self.name}'
    
    class Meta:
        """Metadados do modelo."""
        verbose_name = "Usuário"
        verbose_name_plural = "Usuários"
        ordering = ['id']
