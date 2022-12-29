# official base image
FROM python:3.10.6-slim-buster

# set working directory
WORKDIR /app

# set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
ENV FLASK_ENV development
ENV FLASK_DEBUG 1
ENV APP_SETTINGS project.config.DevelopmentConfig


# install dependencies
COPY requirements.txt .
RUN pip install -r requirements.txt

# add app
COPY . .

# run gunicorn
CMD gunicorn manage:app -w 4 --log-level INFO --bind 0.0.0.0:8000