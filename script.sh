#!/bin/bash
coverage run --omit="*/migrations/*","*/wsgi.py","*/urls.py","*/settings.py","*/production.py","*/apps.py","Api/templatetags/dashboard.py" --source=Api,ErgoApi manage.py test -v 2
coverage report --fail-under=75