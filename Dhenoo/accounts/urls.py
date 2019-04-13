from django.urls import include, path

from . import views

urlpatterns = [
    path('userList', views.MobileUserListView.as_view(),name="userlist"),
]