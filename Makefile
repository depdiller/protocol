build:
	cd ./cmd/gen && go build
	cd ./cmd/crack && go build
	cd ./cmd/verifier && go build
	mv ./cmd/gen/gen ./ && mv ./cmd/verifier/verifier ./ && mv ./cmd/crack/crack ./
container_build:
	docker build --platform linux/amd64 -t depdiller/protocol:latest .
container_run:
	docker run -it depdiller/protocol
rm_all:
	docker ps -aq | xargs docker rm -vf && \
    docker images -aq | xargs docker rmi -f
