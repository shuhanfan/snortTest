import snort.test.Helpers.*;
import snort.test.Bolts.Rule_Bolt;
public class PortMatchTest {
	public PortMatchTest(){};
	public static void main(String[] args) {
		Rule_Header rh = new Rule_Header();
		rh.dport = "13:";
		rh.sport = "!13";
		rh.sip = "10.0.0.1/31";
		rh.dip = "$EXTERNAL_NET";
		
		rh = Rule_Bolt.parseRuleHeader(rh);
		boolean isMatchsport =  rh.portMatch(13, rh.sport_type, rh.sport_val, rh.sport_low, rh.sport_high);
		boolean isMatchdport =  rh.portMatch(13, rh.dport_type, rh.dport_val, rh.dport_low, rh.dport_high);
		System.out.println(rh.dport_type+" "+rh.dport_val+" "+rh.dport_low+" "+rh.dport_high);
		System.out.println(isMatchdport);
		
		
	}
	
	

}
