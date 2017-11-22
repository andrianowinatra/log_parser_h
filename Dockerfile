# Use an official Python runtime as a parent image
FROM python:3.6.3

# Set the working directory to /app
WORKDIR /app

# Copy the current directory contents into the container at /app
ADD . /app

RUN apt-get update && apt-get install libgeoip-dev -y
RUN pip install pipenv
RUN pipenv install --system

# Make port 80 available to the world outside this container
EXPOSE 80

# Define environment variable
ENV NAME World

RUN wget -O CTF1.log https://horangi.box.com/s/9dj3vl4ikzt19td7a9520t7xp4fp1km9
RUN unzip CTF1.log
RUN python parser.py
# Run app.py when the container launches
CMD ["python", "runserver.py"]
