package snort.test.Helpers;

import java.util.ArrayList;
import java.util.regex.Pattern;
public class Rule_Header {
	public String action;
	public String protocol;
	public String sip;	
	public String sport;
	public String direction;
	public String dip;
	public String dport;
	public ArrayList<String> rule_option = new ArrayList<String>(100);
	public ArrayList<RuleOption> parsed_rule_option = new ArrayList<RuleOption>(100);
	
	public boolean equal(Rule_Header r_h){
		if(action.equals(r_h.action)&&protocol.equals(r_h.protocol)&&sip.equals(r_h.sip)&&sport.equals(r_h.sport)&&direction.equals(r_h.direction)&&dip.equals(r_h.dip)&&dport.equals(r_h.dport)){
			return true;
		}else{
			return false;
		}
	}
	public boolean match(Packet_Header pk){
		//System.out.println("in rule heder match packet header:");
		//System.out.println("pkt header-->protocol:"+pk.protocol+",sip:"+pk.sip+",sport:"+pk.sport+",dip:"+pk.dip+",dport:"+pk.dport);
		//System.out.println("rule header-->protocol:"+protocol+",sip:"+sip+",sport:"+sport+",dip:"+dip+",dport:"+dport);
		String sip_tmp = "";
		String dip_tmp = "";
		String pk_protocol = pk.protocol;
		String pk_sip = pk.sip;
		String pk_dip = pk.dip;
		int pk_sport = pk.sport;
		int pk_dport = pk.dport;
		
		boolean isProtocolMatch = protocolMatch(pk_protocol, protocol);
		if(!isProtocolMatch) {
			//System.out.println("protocol dont match");
			return false;
		}	
		boolean isForwardMatch = addrMatch(pk_sip, sip) &&
		          				 addrMatch(pk_dip, dip) &&
		          				 portMatch(pk_sport, sport) &&
		          				 portMatch(pk_dport, dport);
		          
		//System.out.println("> diection match is:"+isForwardMatch);
		if(isForwardMatch) {
			return true;
		}
		if(!direction.equals("<>")) {
			return false;
		}
		boolean isBackwordMatch =  addrMatch(pk_sip, dip) &&
		          				   addrMatch(pk_dip, sip) &&
		                           portMatch(pk_sport, dport) &&
		                           portMatch(pk_dport, sport);
		//System.out.println("< diection match is:"+isBackwordMatch);
		if(isBackwordMatch) {
			return true;
		}
		return false;		
	}
	public Rule_Header(){}
	
	public Rule_Header(String[] r_h,String r_o){
		if(r_h[0].equals("#")) {
			action = r_h[1];
			protocol = r_h[2];
			sip = r_h[3];
			sport = r_h[4];
			direction = r_h[5];
			dip = r_h[6];
			dport = r_h[7];
			rule_option.add(r_o);		
		}
		else {
			action = r_h[0];
			protocol = r_h[1];
			sip = r_h[2];
			sport = r_h[3];
			direction = r_h[4];
			dip = r_h[5];
			dport = r_h[6];
			rule_option.add(r_o);
			
		}
		
	}
	
	public static boolean protocolMatch(String pk_protocol, String rule_protocol) {
	if(rule_protocol.equals(pk_protocol)==false){//proto:ip(tcp(http)/udp/icmp/igmp)/arp/
		if(rule_protocol.equals("ip") ) {
			if(!(pk_protocol.equals("tcp")||pk_protocol.equals("udp")||pk_protocol.equals("icmp")||pk_protocol.equals("igmp")||pk_protocol.equals("http"))){
				//System.out.println("rule_pro==ip and return");
				return false;
			}				
		}
		else if(rule_protocol.equals("tcp")) {
			if(!pk_protocol.equals("http")){
				//System.out.println("rule_pro==tcp,and return");
				return false;
			}								
		}
		else {
			//System.out.println("rule_pro!=ip or tcp and return");
			return false;
		}
		//System.out.println("rule_protocol matches pk_protocol");
		//System.out.println("packet_ptocol);rotocol:"+pk.pro			
	}
	return true;		
}

	public static boolean isInRange(String pk_ip, String rule_ip) {
	String[] networkips = pk_ip.split("\\.");
	int ipAddr = (Integer.parseInt(networkips[0]) << 24)
            | (Integer.parseInt(networkips[1]) << 16)
            | (Integer.parseInt(networkips[2]) << 8)
            | Integer.parseInt(networkips[3]);
    int type = Integer.parseInt(rule_ip.replaceAll(".*/", ""));
    int mask1 = 0xFFFFFFFF << (32 - type);
    String maskIp = rule_ip.replaceAll("/.*", "");
    String[] maskIps = maskIp.split("\\.");
    int cidrIpAddr = (Integer.parseInt(maskIps[0]) << 24)
            | (Integer.parseInt(maskIps[1]) << 16)
            | (Integer.parseInt(maskIps[2]) << 8)
            | Integer.parseInt(maskIps[3]);

    return (ipAddr & mask1) == (cidrIpAddr & mask1);
}

	public static boolean addrMatch(String pk_addr, String rule_addr) {
		if(rule_addr.equals("any"))
			return true;
	//对内外网进行匹配
	String tmp_addr;
	Pattern pattern1 = Pattern.compile("^10.*");
	Pattern pattern2 = Pattern.compile("^172.(16|17|18|19|2[0-9]|30|31).*");
	Pattern pattern3 = Pattern.compile("^192.168.*");
	if(pattern1.matcher(pk_addr).matches()||pattern2.matcher(pk_addr).matches()||pattern3.matcher(pk_addr).matches()){
		//System.out.println("tmp_addr = $HOME_NET");
		tmp_addr = "$HOME_NET";
	}			
	else{
		//System.out.println("tmp_addr = $EXTERNAL_NET");
		tmp_addr = "$EXTERNAL_NET";
	}					
	if(!rule_addr.contains("!")) {//判断rule_addr
		if(!(rule_addr.contains(pk_addr) || rule_addr.equals(tmp_addr))){//如果sip不直接匹配，判断CIDR格式
			if(rule_addr.contains("[")) { //rule_addr list
				String rule_addr_list = rule_addr.substring(1,rule_addr.length()-1);
				//System.out.println("rule_addr_list is:"+rule_addr_list);
				String[] rule_addrs = rule_addr_list.split(",");
				int travel_rule_addrs = 0;
				for(travel_rule_addrs=0; travel_rule_addrs<rule_addrs.length; travel_rule_addrs++) {
					//System.out.println("rule addrs is:"+rule_addrs[travel_rule_addrs]);
					if(rule_addrs[travel_rule_addrs].contains("/")) {//CIDR sip addr只考虑
						//System.out.println("rule addrs is:"+rule_addrs[travel_rule_addrs]);
						if(isInRange(pk_addr, rule_addrs[travel_rule_addrs])) {
							//System.out.println("is in range");
							break;
						}
							
					}						
				}
				if(travel_rule_addrs == rule_addrs.length) {
					//System.out.println("rule_addr dont mactch pk addr list");
					return false;						
				}					
			}
			else {//single rule_addr
				if(!(rule_addr.contains("/") && isInRange(pk_addr, rule_addr))) {//CIDR rule_addr
					//System.out.println(" single rule addr dont match pk addr");
					return false;										
				}					
			}
		}
	}
	else{//rule addr中含有！
		if(rule_addr.contains(pk_addr) || rule_addr.equals(tmp_addr)) {//直接匹配命中
			//System.out.println("! addr and direct match");
			return false;
		}
		if(rule_addr.contains("[")) {//!rule_addr list
			String rule_addr_list = rule_addr.substring(2,rule_addr.length()-1);
			//System.out.println("rule_addr_list is:"+rule_addr_list);
			String[] rule_addrs = rule_addr_list.split(",");
			int travel_rule_addrs = 0;
			for(travel_rule_addrs=0; travel_rule_addrs<rule_addrs.length; travel_rule_addrs++) {
				if(rule_addrs[travel_rule_addrs].contains("/")) {//CIDR sip addr只考虑
					if(isInRange(pk_addr, rule_addrs[travel_rule_addrs])) {
						//System.out.println("! addr and match CIDR list");
						return false;
					}							
				}					
			}
		}
		else{//single rule addr
			if(rule_addr.contains("/") && isInRange(pk_addr, rule_addr)) {//CIDR format
				//System.out.println("!single rule_addr and mactch CIDR");
				return false;
			}			
		}	
	}
	return true;		
}

	public static boolean portMatch(int pk_port, String rule_port) {
	if(rule_port.equals("any")==false){//rule_port
		//System.out.println("rule_port.equals(any)==false");
		if (!rule_port.contains("!")) {
			if (rule_port.contains(""+pk_port)==false){
				//System.out.println("rule_port.contains(pk.sport)==false");
				if(rule_port.contains(":")){
					String[] ports = rule_port.split(":");
					if(ports.length == 1){//500:
						int start_port = Integer.parseInt(ports[0]);
						if(pk_port < start_port)
							return false;
					}
					else {//400:500 or :500
						if("".equals(ports[0])){//:500
							int end_port = Integer.parseInt(ports[1]);
							if(pk_port > end_port)
								return false;
							
						}
						else {//400:500
							int start_port = Integer.parseInt(ports[0]);
							int end_port = Integer.parseInt(ports[1]);
							//System.out.println("the start port is:"+start_port+",end port is:"+end_port);
							if(pk_port > end_port || pk_port < start_port) {
								//System.out.println("pk_port > end_port || pk_port < start_port");
								return false;
							}
						}
					}
					
				}
				else {
					//System.out.println("rule_port dont match pk_port");
					return false;
				}
			}			
		}
		else {// contains !
			rule_port = rule_port.substring(1);
			if (rule_port.contains(""+pk_port)){
				//System.out.println("negative rule_port.contains pk_port");
				return false;
			}
			if(rule_port.contains(":")){
				
				String[] ports = rule_port.split(":");
				if(ports.length  == 1) {//!500:
					int start_port = Integer.parseInt(ports[0]);
					if(pk_port >= start_port)
						return false;
				}
				else{// !:500 or !400:500
					if("".equals(ports[0])){
						int end_port = Integer.parseInt(ports[1]);
						if(pk_port <= end_port)
							return false;
					}
					else{
						int start_port = Integer.parseInt(ports[0]);
						int end_port = Integer.parseInt(ports[1]);
						//System.out.println("negative the start port is:"+start_port+",end port is:"+end_port);
						if(pk_port <= end_port && pk_port >= start_port) {
							//System.out.println("negative pk_port <= end_port && pk_port >= start_port");
							return false;
						}
						
					}
				}
				
			}
			else {
				//System.out.println("negative rule_port dont match pk_port");
				
			}
			
		}
	}
	return true;			
}
	


}
