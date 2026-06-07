FROM ubuntu:22.04

RUN apt-get update
RUN apt-get install -y build-essential python3 python3-pip

COPY . /app
WORKDIR /app
RUN pip3 install -r requirements.txt

ADD ./assets /app/assets

CMD ["python3", "app.py"]
