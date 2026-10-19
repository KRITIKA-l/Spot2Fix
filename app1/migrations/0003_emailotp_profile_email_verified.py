import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app1', '0002_profile_phone_verified'),
    ]

    operations = [
        migrations.RenameField(
            model_name='profile',
            old_name='phone_verified',
            new_name='email_verified',
        ),
        migrations.CreateModel(
            name='EmailOTP',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('code_hash', models.CharField(max_length=128)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('expires_at', models.DateTimeField()),
                ('attempts', models.PositiveSmallIntegerField(default=0)),
                ('used_at', models.DateTimeField(blank=True, null=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='email_otps', to='auth.user')),
            ],
        ),
    ]