package snort.test.Helpers;

import java.io.UnsupportedEncodingException;

import org.jnetpcap.PcapHeader;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.format.FormatUtils;

import org.jnetpcap.protocol.lan.Ethernet;

import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip6;
import org.jnetpcap.protocol.network.Arp;
import org.jnetpcap.protocol.network.Icmp;

import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;
import org.jnetpcap.protocol.tcpip.Http;

import backtype.storm.tuple.Values;

public class CreateValue {
	public String protocol = "null";
	public String sip = "null";
	public String dip = "null";
	public int sport = -1;
	public int dport = -1;
	
	public byte[] payload;//应用层部分
	//ip options
	public boolean sameip = false; //check if source ip is the same as destination ip
	public int dsize = -1;//应用层长度
	public int total_len = -1;//整个报文长度
	public int MF = -1;
	public int DF = -1;
	public int Reserved = -1;
	
	public int ip_proto = -1;//ip protocol,可以是number or name（2 or ICMP）
	public int fragoffset = -1;//ip fragment offset field
	public int ttl = -1;//ip time to live value
	public int tos = -1;
	public int id = -1;
	//public String ipopts = null;//check if a specific IP option is present
	//tcp options
	public int flags = -1;//check if TCP flag bits are present
	public long seq = -1;
	public long ack = -1;
	public int window = -1;//check for a specific TCP window size
	//icmp options
	public int itype = -1;
	public int icode = -1;
	public int icmp_id = -1;
	public int icmp_seq = -1;
	
	
	
	
	
	
	//careful
//	public int payload_offset_from_ip_header= -1;//=payloadOffset-ether_lenth(14);distance from ip header
//	public byte[] binary_packet_from_ip_header=null; //packet from ip header
	
	
	
	

	//not need return
	private Ethernet ether;
	private Ip4 ip4;
	private Ip6 ip6;
	
	private Udp udp;
	private Tcp tcp;
	private Http http;
	private Icmp icmp;
	private Arp arp;
	
	
	public CreateValue(){}
	
	
	public CreateValue(PcapPacket pkt){
		//protocol = "ip";
		//System.out.println("**************************");
		//判断网络层协议
		if(pkt.hasHeader(Ethernet.ID)) {
			
			ether = pkt.getHeader(new Ethernet());
			int ether_type = ether.type();
			total_len = ether.getPayloadLength() + 14;
			//System.out.println("ether.getLength() is:"+ether.getLength());
			
			//System.out.println("ether.getPayloadLength() is:"+ether.getPayloadLength());
			if(ether_type == 0x0800) {//ipv4
				protocol = "ip";
				
				ip4 = pkt.getHeader(new Ip4());
				sip = FormatUtils.ip(ip4.source());
				dip = FormatUtils.ip(ip4.destination());
				//System.out.println("sip is:"+sip);
				//System.out.println("dip is:"+dip);
				if(sip.equals(dip))
					sameip = true;
				MF = ip4.flags_MF();
				DF = ip4.flags_DF();
				Reserved = ip4.flags_Reserved();
				fragoffset = ip4.offset();
				ttl = ip4.ttl();
				tos = ip4.tos();
				id = ip4.id();				
				ip_proto = ip4.type();
				if(ip_proto == 1) {//icmp
					icmp = pkt.getHeader(new Icmp());
					protocol = "icmp";
					payload = icmp.getPayload();
					dsize = icmp.getPayloadLength();
					
					//icmp attribute
					
					//System.out.println("icmp_id = icmp.getId():"+icmp.getId());
					//System.out.println("icmp_hashcode = icmp.hashCode():"+icmp.hashCode());
					//System.out.println("itype = icmp.type():"+icmp.type());
					//System.out.println("icode = icmp.code():"+icmp.code());
					//System.out.println("icmp_id = icmp.getIndex():"+icmp.getIndex());							
					return;
					
				}
				else if (ip_proto == 2) {//igmp
					protocol = "igmp";
					
				}
				else if (ip_proto == 6) {//tcp
					tcp = pkt.getHeader(new Tcp());
					protocol = "tcp";
					sport = tcp.source();
					dport = tcp.destination();
					ack = tcp.ack();
					flags = tcp.flags();
					seq = tcp.seq();
					window = tcp.window();
					//System.out.println("tcp.seq():"+tcp.seq());
					//System.out.println("tcp.windows():"+tcp.window());
					
					
				
					payload = tcp.getPayload();
					dsize = tcp.getPayloadLength();
					if(pkt.hasHeader(Http.ID)) {
						protocol = "http";		
					}
					
				}
				else if(ip_proto == 17) {//udp
					udp = pkt.getHeader(new Udp());
					protocol = "udp";
					sport = udp.source();
					dport = udp.destination();
					payload = udp.getPayload();
					dsize = udp.getPayloadLength();
					return;	
					
				}
				else {//other protocol or ip protocol
					payload = ip4.getPayload();
					dsize = ip4.getPayloadLength();	
					
				}
				
				
			}
			else if(ether_type == 0x86dd) {//ipv6
				protocol = "ip";
				ip6 = pkt.getHeader(new Ip6());
				sip = IPv6BytetoString(ip6.source(), ip6.source().length);
				dip = IPv6BytetoString(ip6.destination(), ip6.destination().length);
				if(pkt.hasHeader(Icmp.ID)) {
					icmp = pkt.getHeader(new Icmp());
					protocol = "icmp";
					ip_proto = 1;
					payload = icmp.getPayload();
					dsize = icmp.getPayloadLength();
					return;
				}
				else if(pkt.hasHeader(Udp.ID)) {
					udp = pkt.getHeader(new Udp());
					protocol = "udp";
					ip_proto = 17;
					sport = udp.source();
					dport = udp.destination();
					payload = udp.getPayload();
					dsize = udp.getPayloadLength();
					return;		
				}
				else if(pkt.hasHeader(Tcp.ID)){
					tcp = pkt.getHeader(new Tcp());
					protocol = "tcp";
					ip_proto = 6;
					sport = tcp.source();
					dport = tcp.destination();
					ack = tcp.ack();
					payload = tcp.getPayload();
					dsize = tcp.getPayloadLength();
					if(pkt.hasHeader(Http.ID)) {
						protocol = "http";		
					}
				}
				else {
					payload = ip6.getPayload();
					dsize = ip6.getPayloadLength();
				}
			}
			else if(ether_type == 0x0806) {//arp
				protocol = "arp";
				arp = pkt.getHeader(new Arp());
				payload = arp.getPayload();
				dsize = arp.getPayloadLength();
			}
		}		
	}
	
	
	public String IPv6BytetoString (byte[] a,int length)
	{
		String cer="";
		if(length==16){
			for(int i=0;i<length;i++)
			{
				String hex=Integer.toHexString(a[i] & 0xFF);
				if(hex.length()==1){
	        		hex ='0'+hex;
	        	}
				if(i%2==1&&i!=length-1){
				cer=cer+hex+":";
				}else{
					cer=cer+hex;
				}
			}
			
		}
		else if(length==4){
			for(int i=0; i<length; i++){
				cer+=a[i];
				if(i<length-1){
					cer+=".";
				}
			}
		}
		
		return cer;
	}
}
