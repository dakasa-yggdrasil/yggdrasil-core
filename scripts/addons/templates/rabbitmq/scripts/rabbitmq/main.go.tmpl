package main

import (
	"fmt"
	"os"

	amqp "github.com/rabbitmq/amqp091-go"
)

func main() {
	brokerURL := os.Getenv("BROKER_URL")
	if brokerURL == "" {
		brokerURL = "amqp://guest:guest@127.0.0.1:5672/"
	}

	conn, err := amqp.Dial(brokerURL)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	if queue := os.Getenv("RABBITMQ_QUEUE"); queue != "" {
		ch, err := conn.Channel()
		if err != nil {
			panic(err)
		}
		defer ch.Close()

		if _, err := ch.QueueDeclarePassive(queue, true, false, false, false, nil); err != nil {
			panic(err)
		}
	}

	fmt.Println("rabbitmq: ok")
}
