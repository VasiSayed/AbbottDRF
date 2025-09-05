from django.contrib import admin

from .models import *
admin.site.register([Event,EventExpert,JoinLog,EventJoin])

