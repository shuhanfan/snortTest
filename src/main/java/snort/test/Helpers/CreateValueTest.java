package snort.test.Helpers;

import java.io.UnsupportedEncodingException;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip6;



public class CreateValueTest {
	public String sip = "null";
	public String dip = "null";
	
	
	private Ip4 ip4;
	private Ip6 ip6;
	
	public CreateValueTest() {};
	
	public  CreateValueTest(PcapPacket pkt)  {
		
		final Ip6 ip6 = new Ip6();
		final Ip4 ip4 = new Ip4();
		//System.out.println("in createValues");
		
		long sec = pkt.getCaptureHeader().seconds();
		int len = pkt.getCaptureHeader().caplen();
		//System.out.println("sec:"+sec);
		//System.out.println("len:"+len);
		//System.out.println("before pkt.hasHeader(Ip4.ID)");
		if(pkt.hasHeader(Ip4.ID))
		{
			//System.out.println("in pkt.hasHeader(Ip4.ID)");
			pkt.getHeader(ip4);
			sip = FormatUtils.ip(ip4.source());
			dip = FormatUtils.ip(ip4.destination());
		}
		else if(pkt.hasHeader(Ip6.ID))
		{
			//System.out.println("in pkt.hasHeader(Ip6.ID)");
			pkt.getHeader(ip6);
			sip = FormatUtils.asStringIp6(ip6.source(),false);
			dip = FormatUtils.asStringIp6(ip6.destination(),false);
		}
		//System.out.println("src:"+src);
		//System.out.println("dst:"+dst);
       
	}

}
