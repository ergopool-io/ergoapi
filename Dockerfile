FROM python:3.7

WORKDIR "/var/www"

RUN mkdir "src"
COPY requirements.txt /var/www/
#RUN apt-get update && apt-get install -y uwsgi uwsgi-plugin-python3 --no-install-recommends && apt-get autoremove --purge

RUN pip3 install uwsgi
RUN pip3 install -r requirements.txt

ADD Api/ /var/www/src/Api/
ADD ErgoApi/ /var/www/src/ErgoApi/
COPY manage.py /var/www/src/
COPY config/uwsgi.ini /var/www/
COPY config/production.py /var/www/src/ErgoApi/

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
ENV POSTGRESQL_ENGINE=django.db.backends.postgresql
ENV POSTGRESQL_PORT=5432
ENV POSTGRESQL_DATABASE=db_api
ENV POSTGRESQL_USER=admin
ENV POSTGRESQL_PASSWORD=admin
ENV POSTGRESQL_HOST=db

WORKDIR "/var/www/src"

CMD ["uwsgi", "--ini", "/var/www/uwsgi.ini"]
