from django.db import models
from django.utils import timezone
from django.core import validators
from django.utils.translation import gettext_lazy as _
from django.contrib.auth.models import (
    AbstractBaseUser, PermissionsMixin, BaseUserManager)
from rest_framework_simplejwt.tokens import RefreshToken


class UserProfileQuerySet(models.QuerySet):
    def find_by_id(self, user_id):
        # return self.filter(user_id=user_id).values()
        return self.filter().get(user_id=user_id)

    def find_by_email(self, email):
        return self.filter(email=email).first()


class UserProfileManager(models.Manager):
    def get_queryset(self):
        return UserProfileQuerySet(self.model, using=self._db)


class UserManager(BaseUserManager, ):
    def _create_user(self, user_name, email, password,
                     is_staff, is_superuser, **extra_fields):
        """
        Creates and saves a User email user_name and password.
        """
        now = timezone.now()
        if not user_name:
            raise ValueError('The given username must be set')
        email = self.normalize_email(email)
        user = self.model(user_name=user_name, email=email,
                          is_staff=is_staff, is_active=True,
                          is_superuser=is_superuser, date_joined=now,
                          **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, user_name, email=None, password=None, **extra_fields):
        return self._create_user(user_name, email, password, False, False,
                                 **extra_fields)

    def create_superuser(self, user_name, email, password, **extra_fields):
        return self._create_user(user_name, email, password, True, True,
                                 **extra_fields)


class UserRegister(AbstractBaseUser, PermissionsMixin):
    user_name = models.CharField(_('username'), max_length=45, unique=True, db_index=True,
                                 help_text=_('Required. 45 characters or fewer. Letters, digits and '
                                             '_.'),
                                 validators=[
                                     validators.RegexValidator(r'^[A-Za-z0-9-._]+$',
                                                               _('Enter a valid username. '
                                                                 'This value may contain only letters, numbers '
                                                                 'and ._ characters.'), 'invalid'),
                                 ],
                                 error_messages={
                                     'unique': _("A user with that username already exists."),
                                 })

    email = models.EmailField(_('email address'), unique=True, db_index=True,
                              help_text=_('Required. a valid email address for verification '),
                              validators=[
                                  validators.RegexValidator(r'^[A-Za-z0-9._@]+$',
                                                            _('Enter a valid email address. '
                                                              'This value may contain only letters, numbers and _@. '),
                                                            'invalid'),
                              ],
                              error_messages={
                                  'unique': _("A user with that email already exists."),
                              })

    first_name = models.CharField(_('first name'), max_length=45, blank=True,
                                  help_text=_('Required. a valid first name'),
                                  validators=[
                                      validators.RegexValidator(r'^[A-Za-z]+$',
                                                                _('Required. a valid name characters. '),
                                                                'invalid'),
                                  ],
                                  error_messages={
                                      '': _("Required. a valid characters."),
                                  })

    last_name = models.CharField(_('last name'), max_length=45, blank=True,
                                 help_text=_('Required. a valid last name'),
                                 validators=[
                                     validators.RegexValidator(r'^[A-Za-z]+$',
                                                               _('Required. a valid name characters. '),
                                                               'invalid'),
                                 ],
                                 error_messages={
                                     '': _("Required. a valid characters."),
                                 })

    mobile_number = models.CharField(_('mobile number'), max_length=45, unique=True, null=False, default='000000000',
                                     editable=True,
                                     help_text=_('Required. a valid mobile number for verification '),
                                     validators=[
                                         validators.RegexValidator(r'^[0-9-._ ]+$',
                                                                   _('Enter a valid mobile number. '
                                                                     'This value may contain only numbers '),
                                                                   'invalid'),
                                     ],
                                     error_messages={
                                         'unique': _("A user with that mobile number already exists."),
                                     })

    is_verified = models.BooleanField(_('verified status'), default=False,
                                      help_text=_('Designates whether this user should be allow to have access.')
                                      )

    is_moderator = models.BooleanField(_('moderator status'), default=False,
                                       help_text=_('Designates whether this user should be treated as moderator.')
                                       )

    is_staff = models.BooleanField(_('staff status'), default=False,
                                   help_text=_('Designates whether the user can log into this admin panel. '))

    is_active = models.BooleanField(_('active statue'), default=False,
                                    help_text=_('Designates whether this user should be treated as '
                                                'active. Deactivate this instead of deleting accounts.'))

    is_superuser = models.BooleanField(_('superuser status'), default=True,
                                       help_text=_('Designates that this user has all permissions without '
                                                   'explicitly assigning them.'))

    date_modified = models.DateTimeField(_('date_modified'), default=timezone.now)
    date_joined = models.DateTimeField(_('date joined'), default=timezone.now)
    timestamp = models.DateTimeField(_('time stamp'), default=timezone.now)

    objects = UserManager()
    user_obj = UserProfileManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['user_name']

    class Meta:
        verbose_name = _('User Register')
        verbose_name_plural = _('User Registers')

    def __str__(self):
        return f"{self.first_name} {self.last_name}"  

    def get_full_name(self):
        """
        Returns the first_name plus the last_name, with a space in between.
        """
        full_name = '%s %s' % (self.first_name, self.last_name)
        return full_name.strip()

    def get_short_name(self):
        "Returns the short name for the user."
        return self.first_name

    def tokens(self):
        refresh = RefreshToken.for_user(self)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token)
        }
