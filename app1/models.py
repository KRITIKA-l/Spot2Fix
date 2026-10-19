from django.db import models
from django.contrib.auth.models import User


# Table 1: Issue
class Issue(models.Model):
    CATEGORY_CHOICES = [
        ('pothole', 'Pothole'),
        ('damaged_road', 'Damaged Road'),
        ('waterlogging', 'Waterlogging'),
        ('garbage', 'Garbage'),
        ('other', 'Other'),
    ]

    STATUS_CHOICES = [
        ('submitted', 'Submitted'),
        ('under_review', 'Under Review'),
        ('in_progress', 'In Progress'),
        ('resolved', 'Resolved'),
    ]

    PRIORITY_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
    ]

    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='issues'
    )
    title = models.CharField(max_length=200)
    description = models.TextField()
    category = models.CharField(
        max_length=30, choices=CATEGORY_CHOICES
    )
    photo = models.ImageField(upload_to='issues/', blank=True, null=True)
    latitude = models.FloatField(blank=True, null=True)
    longitude = models.FloatField(blank=True, null=True)
    priority = models.CharField(
        max_length=10, choices=PRIORITY_CHOICES, default='medium'
    )
    status = models.CharField(
        max_length=20, choices=STATUS_CHOICES, default='submitted'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return self.title


# Table 2: Status History
class StatusHistory(models.Model):
    issue = models.ForeignKey(
        Issue, on_delete=models.CASCADE, related_name='history'
    )
    old_status = models.CharField(max_length=20, blank=True)
    new_status = models.CharField(max_length=20)
    updated_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True
    )
    updated_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.issue.title}: {self.new_status}"


# Table 3: Assignment
class Assignment(models.Model):
    issue = models.ForeignKey(
        Issue, on_delete=models.CASCADE, related_name='assignments'
    )
    assigned_to = models.CharField(max_length=150)
    department = models.CharField(max_length=150, blank=True)
    assigned_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.issue.title} - {self.assigned_to}"


# Table 4: User Profile and Role
class Profile(models.Model):
    ROLE_CHOICES = [
        ('citizen', 'Citizen'),
        ('admin', 'Admin'),
        ('maintenance', 'Maintenance Team'),
    ]

    user = models.OneToOneField(
        User, on_delete=models.CASCADE, related_name='profile'
    )
    role = models.CharField(
        max_length=20, choices=ROLE_CHOICES, default='citizen'
    )
    phone = models.CharField(max_length=15, blank=True)
    email_verified = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.user.username} - {self.role}"


class EmailOTP(models.Model):
    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='email_otps'
    )
    code_hash = models.CharField(max_length=128)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    attempts = models.PositiveSmallIntegerField(default=0)
    used_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"Email OTP for {self.user.username}"
