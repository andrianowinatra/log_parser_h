# Use an official Python runtime as a parent image
FROM python:3.6.3

# Set the working directory to /app
WORKDIR /app

# Copy the current directory contents into the container at /app
ADD . /app

RUN apt-get update && apt-get install libgeoip-dev unzip gzip -y
RUN pip install pipenv
RUN pipenv install --system

# Make port 80 available to the world outside this container
EXPOSE 80

# Define environment variable
ENV NAME World
RUN wget http://geolite.maxmind.com/download/geoip/database/GeoLiteCountry/GeoIP.dat.gz
RUN gzip -d GeoIP.dat.gz

RUN unzip CTF1.zip
RUN python parser.py

# Run app.py when the container launches
CMD ["python", "runserver.py"]
