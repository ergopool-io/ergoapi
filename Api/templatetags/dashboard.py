from django import template
from django.template import Template

register = template.Library()


@register.filter
def subtract(val1, val2):
    try:
        return val1 - val2
    except:
        return 0


@register.filter
def divide(val1, val2):
    try:
        if val1 == 0:
            return 0
        return val1 / val2
    except:
        return 0


@register.filter
def multiply(val1, val2):
    try:
        return val1 * val2
    except:
        return 0
