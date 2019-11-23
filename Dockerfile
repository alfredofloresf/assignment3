# python runtime
FROM python:3.6.5-alpine

# working directory
WORKDIR /app

ENV LC_ALL=c.UTF-8
ENV LANG=C.UTF-8
ENV FLASK_APP=/app/app.py

EXPOSE 5000

RUN apt-get clean && apt-get update -y
RUN apt-get install -y python3-pip
#

COPY . /app
# install requirements
RUN pip3 install -r /app/requirements.txt


CMD ["flask", "run", "-h","0.0.0.0"]
























# FROM alpin:latest
#
# RUN apk update
#
# RUN apk add --no--cache gcc binutils libatomic libgcc libstdc++ gcc libc-dev linux-headers libffl
#
# COPY ./requirements.txt/app/requirements.txt
#
# WORKDIR /app
#
# COPY . /app
#
# EXPOSE 8080
#
# RUN pip3 install -r /app/requirements.txt
#
# RUM rm -r /tmp
# CMD ["flask", "run", "-h","0.0.0.0","-p","8080"]