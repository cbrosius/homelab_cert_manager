# Start from the official Go image
FROM golang:1.20-alpine

# update all
RUN apk update && apk upgrade

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download all dependencies. Dependencies will be cached if the go.mod and go.sum files are not changed
RUN go mod download

# Copy the source from the current directory to the Working Directory inside the container
COPY . .

# create Volumes
VOLUME [ "/app/data" ]

# use Port 8080
EXPOSE 8080

# Build the Go app
RUN go build -o homelab_cert_manager .

# Command to run the executable
CMD ["./homelab_cert_manager"]
