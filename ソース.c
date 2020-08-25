#include<stdio.h>
#include<pcap.h>


FILE* image;

void packet_handler(u_char* args, const struct pcap_pkthdr* header, const u_char* packet) {
	fwrite(packet + 42, header->caplen - 42, 1, image);
	return;
}

int main() {
	char input_path[100];
	printf("pcapファイルのパスを入力してください。\n");
	scanf("%s", input_path);
	char* open_error;
	struct bpf_program* filter;
	pcap_t* descriptor = pcap_open_offline(input_path, open_error);
	if (descriptor == NULL)
	{
		fprintf(stderr, "%s\n", open_error);
		return -1;
	}
	char output_path[100];
	printf("出力ファイルのパスを入力してください。\n");
	scanf("%s", output_path);
	image = fopen(output_path, "ab");
	int compile_error = pcap_compile(descriptor, filter, "icmp[icmptype] = 8", 0, 0);
	if (compile_error < 0)
	{
		pcap_perror(descriptor, "");
		return 1;
	}
	int set_error = pcap_setfilter(descriptor, filter);
	if (set_error < 0)
	{
		pcap_perror(descriptor, "");
	}
	int dispatch_error = pcap_dispatch(descriptor, -1, packet_handler, NULL);
	fclose(image);
	pcap_close(descriptor);
	if (dispatch_error < 0)
	{
		pcap_perror(descriptor, "");
		return -2;
	}
	return 0;
}