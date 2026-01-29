.PHONY: build test test-e2e clean

build:
	go build -o ssh-ca ./cmd/fenrir
	go build -o tyr ./cmd/tyr

test:
	go test -v ./internal/...

test-e2e: clean-test
	docker-compose -f docker-compose.test.yml up --build --abort-on-container-exit --exit-code-from test-runner

clean-test:
	docker-compose -f docker-compose.test.yml down -v --remove-orphans

clean:
	rm -f ssh-ca tyr
	rm -f id_test id_test.pub id_test-cert.pub cookies.txt
