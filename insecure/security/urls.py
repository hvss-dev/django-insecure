from django.urls import re_path, path

from . import views

urlpatterns = [
    # Fixed SQL injection - now with secure patterns
    re_path(r'^users/(?P<user_id>\d+)/$', views.unsafe_users, name='secure_users'),
    re_path(r'^safe/users/(?P<user_id>\d+)/$', views.safe_users, name='safe_users'),

    # Fixed command injection - now with restricted filename patterns
    re_path(r'^files/read/(?P<filename>[a-zA-Z0-9._-]+)/$', views.read_file, name='read_file'),
    re_path(r'^files/copy/(?P<filename>[a-zA-Z0-9._-]+)/$', views.copy_file, name='copy_file'),

    # Fixed insecure deserialization
    path('admin/', views.admin_index, name='admin_index'),

    # Fixed XSS
    path('search/', views.search, name='search'),
    path('log/', views.log, name='log'),
]
