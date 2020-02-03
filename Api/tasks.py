from ErgoApi.celery import app
from Api.utils.share import ValidateShare

ValidateShareTask = app.register_task(ValidateShare())
