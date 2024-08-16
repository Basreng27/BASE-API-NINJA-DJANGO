from django.db import models

# Create your models here.
class Parent(models.Model):
    name = models.CharField(max_length=255)
    number_parent_a = models.IntegerField()
    number_parent_b = models.IntegerField()
    result_parent = models.IntegerField()
    
class Child(models.Model):
    name = models.CharField(max_length=255)
    parent_id = models.ForeignKey(Parent, on_delete=models.CASCADE)
    number_child_a = models.IntegerField()
    number_child_b = models.IntegerField()
    result_child = models.IntegerField()
    result_child_parent = models.IntegerField()
    
class BlacklistedToken(models.Model):
    token = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)