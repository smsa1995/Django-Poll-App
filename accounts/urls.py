

from django.urls import path

from accounts import views


app_name = "accounts"

urlpatterns=[
    path('login/', views.login_user, name='login'),
    path('logout/', views.logout_user, name='logout'),
    path('register/', views.create_user, name='register'),
    path('changepass/', views.change_pass, name='changepass'),
    path('profile/', views.profile, name='profile')
]