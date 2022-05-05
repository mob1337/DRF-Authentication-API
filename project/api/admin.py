from django.contrib import admin
from .models import MyUser, Profile

# Register your models here.
@admin.register(MyUser)
class UserAdmin(admin.ModelAdmin):
    list_display = ['id', 'name', 'email']

@admin.register(Profile)
class ProfileAdmin(admin.ModelAdmin):
    list_display = ['id', 'docfile']