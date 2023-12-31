# Use an official Python runtime as a parent image
FROM python:3.8-slim

# Set the working directory to /app
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Make port 8007 available to the world outside this container
EXPOSE 8007

# Define environment variable
ENV FLASK_APP app.py
ENV FLASK_RUN_HOST 0.0.0.0

# Run app.py when the container launches
CMD ["gunicorn", "-b", "0.0.0.0:8007", "-w", "4", "app:app"]

