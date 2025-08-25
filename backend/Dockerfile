# Выкачиваем из dockerhub образ с python версии 3.9
FROM python:3.9

# Устанавливаем рабочую директорию для проекта в контейнере
WORKDIR /app
COPY requirements.txt /app/requirements.txt
COPY app.py /app/app.py

RUN mkdir /app/download
COPY report.txt /app/download/report.txt

RUN pip3 install --upgrade pip -r requirements.txt

# Устанавливаем порт, который будет использоваться для сервера
EXPOSE 8000

CMD ["python", "app.py"]