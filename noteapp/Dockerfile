FROM python:3

# Make and set the directorties and copy all our files into the docker container
RUN mkdir /noteApp
WORKDIR /noteApp
COPY . .

# Update the packagemanager and install packages

RUN apt-get update
RUN pip3 install -r requirements.txt

EXPOSE 5000