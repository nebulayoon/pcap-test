LDLIBS += -lpcap

all: pcap_parse

pcap_parse: pcap_parse.c

clean:
	rm -f pcap_parse *.o
