from django.contrib import admin
from .models import Issue, StatusHistory, Assignment, Profile

admin.site.register(Issue)
admin.site.register(StatusHistory)
admin.site.register(Assignment)
admin.site.register(Profile)