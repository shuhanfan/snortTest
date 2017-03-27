package snort.test.Helpers;

import java.io.FileWriter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Packet_Header {
	public int version=-1;//4 or 6
	public String protocol="";
	public String sip="";
	public int sport=-1;
	public String dip="";
	public int dport=-1;
	
	public byte[] payload;//抓取到的应用层数据包
	public int dsize;//payload（应用层）的长度
	//规则选项属性
	public int DF;
	public int MF;
	public int Reserved;
	public int ip_proto;//ip protocol的类型，可以是number或者string（2或者IGMP）
	
	//ip options
	public boolean sameip = false; //check if source ip is the same as destination ip
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
	
	
	public int fraLen=14;//以太网帧长，单位字节
	public int ipLen=-1;//ip报头长度，单位为字节
	public int tcpLen=20;//tcp报头长度,单位为字节
	public int udpLen=8;
	
	
	public FileWriter fw;
	
	
	
	
	/*public class OptAttr{
		public int DF;
		public int MF;
		public int Reserved;
		public int ip_proto;
		public int ack=-1;
		public int dsize;
		
	}
	public OptAttr optAttr;	*/
	
	public Packet_Header(){}
	public Packet_Header(byte[] pk){
		try{
		//	fw = new FileWriter("//opt//res4Snort//pcapHeaderParser",true);
			String s1 = BytetoHexString(pk,pk.length);
//			fw.write("The packet is:");
//			fw.write(s1+"\n\n\n\n");
//			
			payload = pk;
			int pcap_header = 16;
			byte[] ether_type_byte=new byte[2];
			ether_type_byte[0]=pk[12+pcap_header];
			ether_type_byte[1]=pk[13+pcap_header];
			int ether_type = BytetoInt(ether_type_byte,2);
			String s = BytetoString(ether_type_byte,2);
			//fw.write(s);
			//fw.flush();
			//if(ether_type == 0x86DD){
			{
				//fw.write("is ip packet");
				//fw.flush();
				//判断是v4 or v6
				protocol = "ip";
				version = (pk[pcap_header+fraLen]&0xf0)/16;
				if (version == 6){
					ipLen=40;
					byte[] ipv6_byte=new byte[40];
					for(int i=0;i<40;i++)
					{
						ipv6_byte[i]=pk[pcap_header+fraLen+i];
					}
					int payload_length=(ipv6_byte[4]&0xff)*16*16+(ipv6_byte[5]&0xff);
					int next_header=(ipv6_byte[6]&0xff);
					byte[] src_byte=new byte[16];
					byte[] dst_byte=new byte[16];
					for(int i=0;i<16;i++){
						src_byte[i]=ipv6_byte[8+i];
						dst_byte[i]=ipv6_byte[8+16+i];
					}
					sip = IPv6BytetoString(src_byte,16);
					dip = IPv6BytetoString(dst_byte,16);
					
					if(next_header==59){//没有下一报头
						protocol = "ip";
						//fw.write("have no next header,protocol=ip\n");
					}
					else {
						while(next_header==0||next_header==43||next_header==44||next_header==60){
							//fw.write("next_header:"+next_header+"\n");
							next_header = pk[pcap_header+fraLen+ipLen]&0xff;
							if(next_header == 44){					
								ipLen +=8;
							}
							else{
								
								ipLen += (pk[pcap_header+fraLen+ipLen+1]&0xff+1)*8;//扩展字头所增加的字节数，以8B为单位，且不包括开头的8B					
							}
						}
						if(next_header==6){
							//fw.write("next_header=6\n");
							protocol = "tcp";
							//start = pcap_header+fraLen+ipLen+tcpLen;
							byte[] tcp_byte=new byte[20];
							for(int i=0;i<tcp_byte.length;i++){
								tcp_byte[i]=pk[pcap_header+fraLen+ipLen+i];
							}
							sport = (tcp_byte[0]&0xff)*16*16+(tcp_byte[1]&0xff);
							dport = (tcp_byte[2]&0xff)*16*16+(tcp_byte[3]&0xff);
							
							
							//考虑是否是http~
//							if(payload.length-pcap_header-fraLen-ipLen-tcpLen>0){//表示tcp下仍有数据
//								//fw.write("tell http~~\n");
//								byte[] app = new byte[payload.length-pcap_header-fraLen-ipLen-tcpLen];
//								int app_len = app.length ;
//								for(int i=0; i<app_len; i++)
//									app[i] = payload[pcap_header+fraLen+ipLen+tcpLen+i];
//								//判断是否含有http的特征字段
//								String str = new String(app, "utf-8");
//								//fw.write("the app content is:\n"+str);
//								String tmp[] = str.split("\r\n\r\n");
//								str = tmp[0];
//								Pattern pattern_http = Pattern.compile("HTTP/...");
//								Matcher matcher_http = pattern_http.matcher(str);
//								if(matcher_http.find()){
//									//fw.write("next_header=http\n");
//									protocol = "http";
//									String tmp2[] = str.split("\r\n");
//								
//								}
//								
//							}
						}
						else if(next_header==17){
							//fw.write("next_header=17\n");
							protocol = "udp";
							//start = pcap_header+fraLen+ipLen+udpLen;
							byte[] udp_byte=new byte[8];
							int udp_byte_len = udp_byte.length;
							for(int i = 0; i < udp_byte_len; i++){
								udp_byte[i]=pk[pcap_header+fraLen+ipLen+i];
							}
							sport = (udp_byte[0]&0xff)*16*16+(udp_byte[1]&0xff);
							dport = (udp_byte[2]&0xff)*16*16+(udp_byte[3]&0xff);
						}
						else if(next_header==58){
							//fw.write("next_header=58\n");
							protocol = "icmp";
						}				
					}
					//fw.write("finish-->>>\n");
					//fw.flush();
					
				}//v6处理结束
				else{//v4报文
					
					ipLen=pk[30]&0x0f;
					ipLen *= 4;
					byte[] ipv4_byte=new byte[ipLen];
					for(int i=0;i<ipLen;i++)
					{
						ipv4_byte[i]=pk[pcap_header+fraLen+i];
					}
					//ipv4的特有属性
					int payload_length=(ipv4_byte[2]&0xff)*16*16+(ipv4_byte[3]&0xff);
					dsize = payload_length;
					int proto=ipv4_byte[9]&0xff;
					
					byte[] src_byte=new byte[4];
					byte[] dst_byte=new byte[4];
					for(int i=0;i<4;i++){
						src_byte[i]=ipv4_byte[12+i];
						dst_byte[i]=ipv4_byte[12+4+i];
					}
					sip = IPv4BytetoString(src_byte,4);
					dip = IPv4BytetoString(dst_byte,4);
					int a = ipv4_byte[5]&0x80;
					
					Reserved=(ipv4_byte[5]&0x80)/128;
					DF=(ipv4_byte[5]&0x40)/64;
					MF=(ipv4_byte[5]&0x20)/32;
					ip_proto=ipv4_byte[9]&0xff;
					//fw.write(optAttr.DF);
					//处理optAttr.ack
//					System.out.println("in packet header");
//					System.out.println(protocol);
//			    	System.out.println(sip);
//			    	System.out.println(sport);
//			    	System.out.println(dip);
//			    	System.out.println(dport);
//			    	System.out.println(ack);
//			    	System.out.println(DF);
//			    	System.out.println(MF);
//			    	System.out.println(Reserved);
//			    	System.out.println(dsize);
//			    	System.out.println(ip_proto);
			//    	fw.flush();
					if(proto==6){
						protocol = "tcp";
						//start = pcap_header+fraLen+ipLen+tcpLen;
						//fw.write("next_header:tcp");
						byte[] tcp_byte=new byte[20];
						int tcp_byte_len = tcp_byte.length;
						for(int i = 0; i < tcp_byte_len; i++){
							tcp_byte[i]=pk[pcap_header+fraLen+ipLen+i];
						}
						sport = (tcp_byte[0]&0xff)*16*16+(tcp_byte[1]&0xff);
						dport = (tcp_byte[2]&0xff)*16*16+(tcp_byte[3]&0xff);
						ack = tcp_byte[13]&0x10/16;
						
						//考虑是否是http~
						if(payload.length-pcap_header-fraLen-ipLen-tcpLen>0){//表示tcp下仍有数据
							//fw.write("tell http~~\n");
							byte[] app = new byte[payload.length-pcap_header-fraLen-ipLen-tcpLen];
							int app_len = app.length;
							for(int i=0; i<app_len; i++)
								app[i] = payload[pcap_header+fraLen+ipLen+tcpLen+i];
							//判断是否含有http的特征字段
							String str = new String(app, "utf-8");
							//fw.write("the app content is:\n"+str);
							String tmp[] = str.split("\r\n\r\n");
							str = tmp[0];
							Pattern pattern_http = Pattern.compile("HTTP/...");
							Matcher matcher_http = pattern_http.matcher(str);
							if(matcher_http.find()){
								protocol = "http";
								String tmp2[] = str.split("\r\n");
								
							}
							
						}
					}
					else if(proto==1){
						protocol = "icmp";
					}
						
					else if(proto==17){
						protocol = "udp";
						//start = pcap_header+fraLen+ipLen+tcpLen;
						//fw.write("next_header:udp");
					}
//					fw.write("the protocol is:"+protocol+"the src is:"+sip+"the dip is:"+dip+"the sport is:"+sport+"the dport is:"+dport+"\n\n\n");
//					fw.flush();
						
				}//全都是ipv4的内容
					
			}
				
			
			
//		}catch (IOException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
		}catch(UnsupportedEncodingException e){
			e.printStackTrace();
		}
	}
	
	public int BytetoInt (byte[] a,int length)
	{
		
		int cer=0;
		for(int i=0;i<length;i++)
		{
			cer=cer*16*16;
			cer=cer+(a[i]&0xff);
		}
		return cer;
	}
	
	public String IPv4BytetoString (byte[] a,int length)
	{
		String cer="";
		for(int i=0;i<length;i++)
		{
			String hex=Integer.toString(a[i]&0xFF);
			if(i!=length-1){
        		hex =hex+".";
        	}
			
				cer=cer+hex;
			
		}
		return cer;
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
	
	public String BytetoString (byte[] a,int length)
	{
		String cer="";
		for(int i=0;i<length;i++)
		{
			String hex=Integer.toBinaryString(a[i]&0xFF);
			if(hex.length()==1){
        		hex ='0'+hex;
        	}
			
				cer=cer+hex;
			
		}
		return cer;
	}
	
	public String BytetoHexString (byte[] a,int length)
	{
		String cer="";
		for(int i=0;i<length;i++)
		{
			String hex=Integer.toHexString(a[i]&0xFF);
			if(hex.length()==1){
        		hex ='0'+hex;
        	}
			
				cer=cer+hex;
			
		}
		return cer;
	}
}
