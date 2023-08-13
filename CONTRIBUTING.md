# CONTRIBUTING

## How to run the Docker file locally

```commandline
docker run dp 5005:5000 -w /app -v "$(pwd):/app" IMAGE_NAME sh -c "flask run --host 0.0.0.0"
```