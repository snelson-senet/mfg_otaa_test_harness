import semtech_packet_forwarder 
import getopt, sys

DEFAULT_PORT = 2000

def display_help():
    print("Test Device Server Help")
    print("--port <portnum>")
    print("--help")


if __name__ == "__main__":
    shortopts = []
    longopts = ["help", "port="]
    port = DEFAULT_PORT 

    try:
        arguments, values = getopt.getopt(sys.argv[1:], shortopts, longopts)
    except getopt.error as err:
        print(str(err))
        sys.exit(2)

    for option, value in arguments:
        if option in ("--port"):
            port = int(value)
        elif option in ("--help"):
            display_help()
            sys.exit(0)

    protocol = semtech_packet_forwarder.Protocol("127.0.0.1", port)
    protocol.run()