"""
URL configuration for project1 project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.conf.urls.static import static
from django.conf import settings
from django.http import HttpResponse
from django.urls import path

from app1 import views


def coming_soon(request):
    return HttpResponse("This Spot2Fix page is under development.")


urlpatterns = [
    # Public pages
    path('', views.home, name='home'),
    path('issues/', views.issue_list, name='issue_list'),
    path('citizen/search/', views.issue_list, name='search_issues'),

    # Authentication
    path('signup/', views.signupuser, name='signupuser'),
    path('login/', views.loginuser, name='loginuser'),
    path('verify-otp/', views.verify_otp, name='verify_otp'),
    path('resend-otp/', views.resend_otp, name='resend_otp'),
    path('logout/', views.logoutuser, name='logoutuser'),
    path('profile/', coming_soon, name='profile'),

    # Citizen features
    path('citizen/dashboard/', views.citizen_dashboard, name='citizen_dashboard'),
    path('citizen/report/', views.report_issue, name='report_issue'),
    path('citizen/my-issues/', views.my_reports, name='my_issues'),

    # Admin features
    path('admin/dashboard/', views.admin_dashboard, name='admin_dashboard'),
    path('admin/issue/<int:issue_id>/action/', views.admin_issue_action, name='admin_issue_action'),

    # Maintenance features
    path('maintenance/dashboard/', views.maintenance_dashboard, name='maintenance_dashboard'),
    path('maintenance/recommendations/', views.maintenance_recommendations, name='maintenance_recommendations'),
    path('maintenance/issue/<int:issue_id>/action/', views.maintenance_issue_action, name='maintenance_issue_action'),
    path('maintenance/assigned-issues/', coming_soon, name='assigned_issues'),

    # Django built-in admin must remain after custom admin routes.
    path('admin/', admin.site.urls),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT,)