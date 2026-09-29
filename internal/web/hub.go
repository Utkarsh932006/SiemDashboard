package web

type Message struct {
	Event string
	Data  string
}

type Hub struct {
	clients    map[chan Message]bool
	broadcasts chan Message
	register   chan chan Message
	unregister chan chan Message
}

func NewHub() *Hub {
	return &Hub{
		clients:    make(map[chan Message]bool),
		broadcasts: make(chan Message),
		register:   make(chan chan Message),
		unregister: make(chan chan Message),
	}
}

func (h *Hub) Run() {
	for {
		select {
		case client := <-h.register:
			h.clients[client] = true
		case client := <-h.unregister:
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client)
			}
		case msg := <-h.broadcasts:
			for client := range h.clients {
				select {
				case client <- msg:
				//sent successfully
				default:
					delete(h.clients, client)
					close(client)
				}
			}
		}
	}
}

func (h *Hub) Broadcast(event string, data string) {
	h.broadcasts <- Message{
		Event: event,
		Data:  data,
	}
}
