from django.contrib import admin
from django.utils.translation import gettext_lazy as _
from ango_portal_server.authentication.models import UserRegister
from django.contrib.auth.admin import UserAdmin


class UserAdminConfig(UserAdmin):
    model = UserRegister

    # ADMIN EDITABLE
    fieldsets = (
        (None, {'fields': ('user_name', 'password')}),
        (_('Personal info'), {'fields': ('first_name', 'last_name', 'mobile_number', 'email')}),
        (_('Permissions'), {'fields': ('is_verified', 'is_active', 'is_moderator', 'is_staff',
                                       'is_superuser', 'groups', 'user_permissions')}),
        (_('Important dates'), {'fields': ('last_login', 'date_joined')}),
    )
    # CREATE SUPERUSER
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('user_name', 'password1', 'password2', 'mobile_number'),
        }),
    )
    # ADMIN VIEWS
    list_display = ('id', 'user_name', 'email', 'first_name', 'last_name', 'mobile_number',
                    'is_active', 'is_verified', 'is_staff', 'is_moderator', 'is_superuser',
                    'last_login', 'date_modified', 'date_joined', 'timestamp')

    # ADMIN KEYWORD SEARCHABLE FIELDS
    list_filter = ('is_active', 'is_staff', 'is_superuser', 'groups')
    search_fields = ('user_name', 'email', 'first_name', 'last_name')
    ordering = ('user_name',)
    filter_horizontal = ('groups', 'user_permissions',)


admin.site.register(UserRegister, UserAdminConfig)




#accountAuthToken