"""Testes para verificar restrições de métodos HTTP nas views de segurança.

Este módulo testa se as views admin_index, search e log estão corretamente
restringidas apenas ao método GET, conforme exigido pelo SonarQube.
"""

import django
from django.test import TestCase, Client
import os

# Configure Django settings
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "insecure.settings_test")
django.setup()


class HTTPMethodsTestCase(TestCase):
    """Testa restrições de métodos HTTP para views de segurança."""

    def setUp(self):
        """Configura o cliente de teste."""
        self.client = Client()

    def test_admin_index_only_allows_get(self):
        """Testa se admin_index aceita apenas GET."""
        # GET deve funcionar (mesmo sem token válido, deve retornar 401)
        response = self.client.get("/security/admin/")
        self.assertIn(response.status_code, [200, 401])  # Aceita GET

        # POST deve ser rejeitado com 405 Method Not Allowed
        response = self.client.post("/security/admin/")
        self.assertEqual(response.status_code, 405)

        # PUT deve ser rejeitado com 405 Method Not Allowed
        response = self.client.put("/security/admin/")
        self.assertEqual(response.status_code, 405)

        # DELETE deve ser rejeitado com 405 Method Not Allowed
        response = self.client.delete("/security/admin/")
        self.assertEqual(response.status_code, 405)

    def test_search_only_allows_get(self):
        """Testa se search aceita apenas GET."""
        # GET deve funcionar
        response = self.client.get("/security/search/", {"query": "test"})
        self.assertEqual(response.status_code, 200)

        # POST deve ser rejeitado com 405 Method Not Allowed
        response = self.client.post("/security/search/", {"query": "test"})
        self.assertEqual(response.status_code, 405)

        # PUT deve ser rejeitado com 405 Method Not Allowed
        response = self.client.put("/security/search/", {"query": "test"})
        self.assertEqual(response.status_code, 405)

        # DELETE deve ser rejeitado com 405 Method Not Allowed
        response = self.client.delete("/security/search/")
        self.assertEqual(response.status_code, 405)

    def test_log_only_allows_get(self):
        """Testa se log aceita apenas GET."""
        # GET deve funcionar
        response = self.client.get("/security/log/", {"string": "test log"})
        self.assertEqual(response.status_code, 200)

        # POST deve ser rejeitado com 405 Method Not Allowed
        response = self.client.post("/security/log/", {"string": "test log"})
        self.assertEqual(response.status_code, 405)

        # PUT deve ser rejeitado com 405 Method Not Allowed
        response = self.client.put("/security/log/", {"string": "test log"})
        self.assertEqual(response.status_code, 405)

        # DELETE deve ser rejeitado com 405 Method Not Allowed
        response = self.client.delete("/security/log/")
        self.assertEqual(response.status_code, 405)

    def test_http_method_security_headers(self):
        """Testa se os cabeçalhos de segurança estão presentes nas respostas GET."""
        # Testa search com cabeçalhos de segurança
        response = self.client.get("/security/search/", {"query": "test"})
        self.assertEqual(response.status_code, 200)
        self.assertIn("X-XSS-Protection", response)
        self.assertIn("Content-Security-Policy", response)

        # Testa log
        response = self.client.get("/security/log/", {"string": "test"})
        self.assertEqual(response.status_code, 200)

        # Verifica que métodos não permitidos não retornam cabeçalhos específicos
        response = self.client.post("/security/search/", {"query": "test"})
        self.assertEqual(response.status_code, 405)
        # Método não permitido não deve processar a lógica da view
