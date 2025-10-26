# Stage 1 - Build Stage
FROM python:3.12.11-alpine3.20 AS builder

# Install system dependencies, upgrade packages, and create a non-root user
RUN apk update && apk upgrade \
    && groupadd --gid 1000 appuser \
    && useradd --uid 1000 --gid 1000 -ms /bin/bash appuser

# Install pip and virtualenv
RUN pip install --no-cache-dir --upgrade pip virtualenv

# Install build essentials and other necessary tools
RUN apk add --no-cache build-base git

# Switch to the non-root user
USER appuser

# Set the working directory
WORKDIR /home/appuser

# Copy the source code into the container
COPY . /home/appuser/

# Set environment variables
ENV VIRTUAL_ENV="/home/appuser/venv"
ENV LC_ALL=es_AR.utf8
ENV LANG=es_AR.utf8
ENV LANGUAGE=es_AR.utf8
ENV TZ=America/Argentina/Buenos_Aires

# Create and activate the virtual environment, and install dependencies
RUN python -m venv ${VIRTUAL_ENV}
RUN . ${VIRTUAL_ENV}/bin/activate && pip install -r requirements.txt

FROM python:3.12.11-alpine3.20 AS production
# Upgrade packages and create a non-root user to run the application
RUN apk update && apk upgrade \
    && groupadd --system appuser \
    && useradd --system --gid appuser appuser

# Switch to the non-root user
USER appuser

# Set the working directory
WORKDIR /home/appuser

# Copy from the first stage
COPY --from=builder /home/appuser /home/appuser

# Set environment variables
ENV TZ=America/Argentina/Buenos_Aires

# Expose the port
EXPOSE 8501

# Copy the run script to the image and set as entrypoint
COPY run.sh /home/appuser
ENTRYPOINT ["./run.sh"]