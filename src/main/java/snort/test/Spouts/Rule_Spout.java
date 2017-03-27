
package snort.test.Spouts;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import snort.test.Helpers.*;
import backtype.storm.spout.SpoutOutputCollector;
import backtype.storm.task.TopologyContext;
import backtype.storm.topology.IRichSpout;
import backtype.storm.topology.OutputFieldsDeclarer;
import backtype.storm.tuple.Fields;
import backtype.storm.tuple.Values;

import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;






public class Rule_Spout implements IRichSpout {

	private SpoutOutputCollector outputCollector;
	private  FileInputStream fis;
    private  InputStreamReader isr ;
	private  BufferedReader br ;
	private String str;
	private String ruleFile = "";
	private int count;
	private boolean once;
	private ArrayList<Rule_Header> rhset;
	
	public Rule_Spout(String fileName){
		ruleFile = fileName;
	}
	public Rule_Spout(){
		
	}
	public void open(Map arg0, TopologyContext arg1, SpoutOutputCollector spoutOutputCollector) {
		// TODO Auto-generated method stub
		this.outputCollector = spoutOutputCollector;		
        try {  	
        	if(ruleFile.equals("")){
        		fis = new FileInputStream("//opt//res4Snort//small_rules.txt");
        	}
        	else
        		fis = new FileInputStream(ruleFile);
        	isr = new InputStreamReader(fis);
    		br = new BufferedReader(isr);
    		str=null;
    		rhset = new ArrayList<Rule_Header>(500);
    		count=0;
    		once=true;
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
	}
	
	public void nextTuple() {
		//int flag=0;
		// TODO Auto-generated method stub
		//System.out.println("This is before nextTuple try");
		try{
			if ((str = br.readLine()) != null){
				if(shouldFilter(str))
					return;//filter unrealized rules
				
				count++;
				///***///
				System.out.println("count:"+count);
				String aaa="\\(";
				String rule_header=null;
				String rule_option=null;
				Pattern pattern_web = Pattern.compile(aaa);	
				Matcher matcher_web = pattern_web.matcher(str);
				if (matcher_web.find()) {
					rule_header = str.substring(0, matcher_web.start());
					///***///
					System.out.println("rule_header:"+rule_header);
					rule_option = str.substring(matcher_web.start(),str.length());
					///***///
					System.out.println("rule_option:"+rule_option);
					
					String tmp[]=rule_header.split(" ");
					Rule_Header tmp_header = new Rule_Header(tmp,rule_option);
					int hea_i = 0;
					int rhset_size = rhset.size();
					for(hea_i = 0; hea_i < rhset_size; hea_i++){
						if(rhset.get(hea_i).equal(tmp_header)==true){
							rhset.get(hea_i).rule_option.add(rule_option);
							break;
						}
					}
					if(hea_i==rhset_size){
						rhset.add(tmp_header);
						
					}
				}
				
				
				
			}else{
				if(once == true){
					int rhset_size = rhset.size();
					for(int i = 0;i < rhset_size; i++){
						this.outputCollector.emit("rule",new Values(rhset.get(i).action,rhset.get(i).protocol,rhset.get(i).sip,rhset.get(i).sport,rhset.get(i).direction,rhset.get(i).dip,rhset.get(i).dport,rhset.get(i).rule_option,false));
						///***///
						System.out.println("No.:"+i+",rule_option.size:"+rhset.get(i).rule_option.size()+",action:"+rhset.get(i).action+",protocol:"+rhset.get(i).protocol+",sip:"+rhset.get(i).sip+",sport:"+rhset.get(i).sport+",direction:"+rhset.get(i).direction+",dip:"+rhset.get(i).dip+",dport:"+rhset.get(i).dport);
						for(int j=0; j<rhset.get(i).rule_option.size(); j++) {
							System.out.println("here:"+rhset.get(i).rule_option.get(j));
						}
					}
					this.outputCollector.emit("rule",new Values("action","protocol","sip","sport","direction","dip","dport","option",true));
				}
				once = false;
			}
		} catch(Exception e) {
					e.printStackTrace();
			    	System.out.println("rule spout fail to deal with rules");
			    }
	}
	
	public static boolean shouldFilter(String str) {
		if(str.contains("; flowbits")||str.contains("; itype")||str.contains("; icode")||str.contains("; icmp_id")||str.contains("; icmp_seq")||str.contains("; stream_reassemble")||str.contains("; stream_size")
				||str.contains("; protected_content")||str.contains("; hash")||str.contains("; length")||str.contains("; rawbytes")||str.contains("; base64_decode")||str.contains("; base64_data")||str.contains("; byte_test")||str.contains("; byte_jump")||str.contains("; byte_extract")||str.contains("; byte_math")||str.contains("; http")||str.contains("; fast_pattrn")||str.contains("; uricontent")||str.contains("; urilen")||str.contains("; file_data")||str.contains("; pcre")||str.contains("; ftpbounce")||str.contains("; asn1")||str.contains("; cvs")||str.contains("; dce")||str.contains("; sip")||str.contains("; gtp")||str.contains("ssl"))
			return true;
		return false;
	}
	
	public void declareOutputFields(OutputFieldsDeclarer outputFieldsDeclarer) {
		// TODO Auto-generated method stub
		//outputFieldsDeclarer.declare(new Pcap().createFields());
		outputFieldsDeclarer.declareStream("rule",new Fields("action","protocol","sip","sport","direction","dip","dport","option","switch"));
//		outputFieldsDeclarer.declareStream("basic",new Fields("sec","src","dst","len"));//后面bolt都依据这个方法来定义字段
//		outputFieldsDeclarer.declareStream("udp",new Fields("sec","src","dst","len","src_port","dst_port"));
//		outputFieldsDeclarer.declareStream("tcp",new Fields("sec","src","dst","len","src_port","dst_port"));
//		//outputFieldsDeclarer.declareStream("ip",new Fields("sec","src","dst","len"));
//		outputFieldsDeclarer.declareStream("http",new Fields());
		//outputFieldsDeclarer.declareStream("switch",new Fields("transfer"));
	}

	public Map<String, Object> getComponentConfiguration() {
		// TODO Auto-generated method stub
		return null;
	}

	
	
    	public void ack(Object arg0) {
    		// TODO Auto-generated method stub
    		
    	}

    	public void activate() {
    		// TODO Auto-generated method stub
    		
    	}

    	public void close() {
    		// TODO Auto-generated method stub
    	}

    	public void deactivate() {
    		// TODO Auto-generated method stub
    		
    	}

    	public void fail(Object arg0) {
    		// TODO Auto-generated method stub
    		
    	}

}
