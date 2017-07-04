package snort.test.Bolts;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.Map;

import backtype.storm.task.OutputCollector;
import backtype.storm.task.TopologyContext;
import backtype.storm.topology.BasicOutputCollector;
import backtype.storm.topology.FailedException;
import backtype.storm.topology.IBasicBolt;
import backtype.storm.topology.OutputFieldsDeclarer;
import backtype.storm.tuple.Fields;
import backtype.storm.tuple.Tuple;
import backtype.storm.tuple.Values;

import java.io.*; 

import snort.test.Helpers.Packet_Header;
import snort.test.Helpers.Rule_Header;
import snort.test.Helpers.DealOption;
import snort.test.Helpers.RuleOption;


public class Rule_Bolt implements IBasicBolt{

	private BasicOutputCollector outputCollector;
	private ArrayList<Rule_Header> rule_set;
//	public FileWriter fwRule ;
//	public FileWriter fw ;
	
	
	
	private String name_bolt;
	private long pktlen = 0;//record the transport flow
	private int packnum =0;
	private int receivednum = 0;
	private int payloadnum = 0;
	//private int detect = 0;
	  //private int ruleBoltType = 0;
	
	
	
	private long lastTime = 0;
	private long duringTime = 0;
	private long curTime = 0;
	private boolean transfer = false;
	//private Values emitVal = new Values();
	Packet_Header pcaket_tmp;
	Rule_Header rule_tmp;
	
	
	public Rule_Bolt(String nm){
		name_bolt =nm;
	}
	public void declareOutputFields(OutputFieldsDeclarer declarer) {
		// TODO Auto-generated method stub
		declarer.declareStream("result",new Fields("time","packnum", "flow"));
		declarer.declareStream("payload",new Fields("ruleNumber","protocol","sip","sport","dip","dport","dsize","ip_proto","DF","MF","Reserved","fragoffset","ttl","tos","id","flags","seq","ack","window","sameip","payload","total_len"));
		//outputFieldsDeclarer.declareStream("volume",new Fields("protocol","sip","sport","dip","dport"));
		//declarer.declare(new Fields("payload"));
	}

	public Map<String, Object> getComponentConfiguration() {
		// TODO Auto-generated method stub
		return null;
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
	public void prepare(Map stormConf, TopologyContext context) {
		packnum = 0;
		rule_set = new ArrayList<Rule_Header>(110);
		lastTime = System.currentTimeMillis()/1000;
		
		pcaket_tmp = new Packet_Header();
		rule_tmp = new Rule_Header();
//		try {
//			if(name_bolt.equals("RuleBolt1")){
//				ruleBoltType = 1;
//				fwRule = new FileWriter("//opt//res4Snort//rulespout_ruleBolt1");
//				fw = new FileWriter("//opt//res4Snort//headerMatch");
//			}
//			else if(name_bolt.equals("RuleBolt2")){
//				ruleBoltType = 2;
//				fwRule = new FileWriter("//opt//res4Snort//rulespout_ruleBolt2");
//				fwVol = new FileWriter("//opt//res4Snort//volspout_ruleBolt2");
//			}	
//			else if(name_bolt.equals("RuleBolt3")){
//				ruleBoltType = 3;
//				fwRule = new FileWriter("//opt//res4Snort//rulespout_ruleBolt3");
//				fwVol = new FileWriter("//opt//res4Snort//volspout_ruleBolt3");
//			}
//		}catch(IOException e){
//			System.out.println(e.getMessage());
//		}
			
			
		
		// TODO Auto-generated method stub
		
	}

	public void execute(Tuple tuple, BasicOutputCollector collector) {
		// TODO Auto-generated method stub
		outputCollector = collector;
		outputCollector.setContext(tuple);  
		String name=tuple.getSourceStreamId();  
		try {
			//System.out.println("in rule_bolt of execute");
			//每s固定发一次给ResultBolt
			curTime = System.currentTimeMillis()/1000;
			duringTime = curTime -lastTime;
			//System.out.println("duringTime in rulebolt is:"+duringTime);
	    	if(duringTime>=1) {
	    		this.outputCollector.emit("result",new Values(curTime, packnum, pktlen));
	    		//测试从volumeSpout发送到result接收的速率
	    	    System.out.println("in RuleBolt to result(pps):"+packnum+"/"+curTime+"s");
	    		receivednum =0;
	    		pktlen = 0;
	    		packnum= 0;
	    		lastTime = curTime;
	    	}
			if(name.equals("volume")){
				if (!transfer)
					return;				
				
				boolean matched = false;
				//System.out.println("rule bolt for vol");
				receivednum++;
				//测试rule_bolt的整体效率pps
				
				/*
				curTime = System.currentTimeMillis()/1000;
				duringTime = curTime -lastTime;
		    	if(duringTime>=1) {
		    		System.out.println("in Rule Bolt count(pps):"+packnum);
		    		packnum =0;
		    		lastTime = curTime;
		    	}
		    	*/
		    	
		    		
		    	
				
				//测试rule_bolt的处理一个包的时长
		    	/*
				curTime = System.currentTimeMillis();
				duringTime = curTime - lastTime;
				lastTime = curTime;
				System.out.println("in rule_bolt period is:"+duringTime);
				*/
				pcaket_tmp.protocol = (String)tuple.getValueByField("protocol");
				pcaket_tmp.sip = (String)tuple.getValueByField("sip");
				pcaket_tmp.sport=(Integer)tuple.getValueByField("sport");
				pcaket_tmp.dip=(String)tuple.getValueByField("dip");
				pcaket_tmp.dport=(Integer)tuple.getValueByField("dport");
				pcaket_tmp.payload=(byte[])tuple.getValueByField("payload");
				pcaket_tmp.ack = (Long)tuple.getValueByField("ack");
				pcaket_tmp.DF = (Integer)tuple.getValueByField("DF");
				pcaket_tmp.dsize = (Integer)tuple.getValueByField("dsize");
				pcaket_tmp.ip_proto = (Integer)tuple.getValueByField("ip_proto");
				pcaket_tmp.Reserved= (Integer)tuple.getValueByField("Reserved");
				pcaket_tmp.fragoffset = (Integer)tuple.getValueByField("fragoffset");
				pcaket_tmp.ttl = (Integer)tuple.getValueByField("ttl");
				pcaket_tmp.tos = (Integer)tuple.getValueByField("tos");
				pcaket_tmp.id = (Integer)tuple.getValueByField("id");
				pcaket_tmp.flags = (Integer)tuple.getValueByField("flags");
				pcaket_tmp.seq = (Long)tuple.getValueByField("seq");
				pcaket_tmp.window = (Integer)tuple.getValueByField("window");
				pcaket_tmp.sameip = (Boolean) tuple.getValueByField("sameip");
				pcaket_tmp.sip_val = convertAddrStr2Int(pcaket_tmp.sip);
				pcaket_tmp.dip_val = convertAddrStr2Int(pcaket_tmp.dip);
				int total_len =  (Integer)tuple.getValueByField("total_len");
				pktlen += total_len;
	//			String p = BytetoString(pcaket_tmp.payload,pcaket_tmp.payload.length);
				
				//System.out.println("pkheader.protocol:"+pcaket_tmp.protocol+" pkheader.sip:"+pcaket_tmp.sip+" pkheader.sport:"+pcaket_tmp.sport+" pkheader.dip:"+pcaket_tmp.dip+" pkheader.dport:"+pcaket_tmp.dport);
				
				//对数据包进行处
				//System.out.println(" before deal with packet using rules");
				
				
				
				
				
				//long rule_header_start = System.nanoTime();
				//System.out.println("name:"+name_bolt+"rule_set_size:"+rule_set.size());
				int rule_size = rule_set.size();
				for(int i=0; i<rule_size; i++){
					//System.out.println("in deal packet loop");
					//System.out.println("the rule is"+rule_set.get(i).action+" "+rule_set.get(i).action+" "+rule_set.get(i).sip+" "+rule_set.get(i).sport+" "+rule_set.get(i).dip+" "+rule_set.get(i).dport);
					
					if(rule_set.get(i).match(pcaket_tmp)){//选择规则选项匹配的规则进行处理
						//测试发送给Payload_Bolt的效率
						
						payloadnum++;
						curTime = System.currentTimeMillis()/1000;
						duringTime = curTime -lastTime;
				    	if(duringTime>=1) {
				    		System.out.println("in RuleBolt send to PayloadBolt count(pps):"+payloadnum+"/"+curTime+"s");
				    		payloadnum =0;
				    		lastTime = curTime;
				    	}
				    	
				    	
				    	
						
						this.outputCollector.emit("payload",new Values(i,pcaket_tmp.protocol,pcaket_tmp.sip,pcaket_tmp.sport,pcaket_tmp.dip,pcaket_tmp.dport,pcaket_tmp.dsize,pcaket_tmp.ip_proto,pcaket_tmp.DF,pcaket_tmp.MF,pcaket_tmp.Reserved,pcaket_tmp.fragoffset,pcaket_tmp.ttl,pcaket_tmp.tos,pcaket_tmp.id,pcaket_tmp.flags,pcaket_tmp.seq,pcaket_tmp.ack,pcaket_tmp.window,pcaket_tmp.sameip,pcaket_tmp.payload,total_len));
						
						matched = true;
						
					}
					
					
//					
				}
				//逻辑改为每一秒再固定发一次
				
				if(!matched)
					packnum++;
					
				
				
				//测试rule_header_match函数的效率
				/*
				long rule_header_end = System.nanoTime();
				long rule_header_during = rule_header_end - rule_header_start;
				System.out.println("in ruleHeaderMatch period:"+rule_header_during);
				*/
				//System.out.println("pkheader.protocol:"+pcaket_tmp.protocol+" pkheader.sip:"+pcaket_tmp.sip+" pkheader.sport:"+pcaket_tmp.sport+" pkheader.dip:"+pcaket_tmp.dip+" pkheader.dport:"+pcaket_tmp.dport);
			}
			else if(name.equals("rule") )
			{				
				
				transfer = (Boolean)tuple.getValueByField("switch");
				if(transfer) {
					//打印出rule_set的内容
					/*
					System.out.println("in rulebolt:");
					
					for(int i = 0; i < rule_set.size(); i++) {
						System.out.println("the "+i+ " rule is:"+rule_set.get(i).action+" "+rule_set.get(i).action+" "+rule_set.get(i).sip+" "+rule_set.get(i).sport+" "+rule_set.get(i).dip+" "+rule_set.get(i).dport);
						
					}*/
					return;
				}
				//System.out.println("rule bolt for rule");
				
				rule_tmp.action=(String)tuple.getValueByField("action");
				rule_tmp.protocol=(String)tuple.getValueByField("protocol");
				rule_tmp.sip=(String)tuple.getValueByField("sip");
				rule_tmp.sport=(String)tuple.getValueByField("sport");
				rule_tmp.direction=(String)tuple.getValueByField("direction");
				rule_tmp.dip=(String)tuple.getValueByField("dip");
				rule_tmp.dport=(String)tuple.getValueByField("dport");
				rule_tmp.rule_option=(ArrayList)tuple.getValueByField("option");
				
				rule_tmp = parseRuleHeader(rule_tmp);
				//get parsed_rule_option
				//rule_tmp.parsed_rule_option = parseRuleOption(rule_tmp.rule_option);
				rule_set.add(rule_tmp);			
				
			}
		} catch(FailedException e) {
	    	System.out.println("in ruleBolt"+e.getMessage());
	    } 

	}
	
	public static boolean isIgnore(String s) {
		 if(s.equals(" classtype")||s.equals(" metadata")||s.equals(" rev")||s.equals(" sid")||s.equals(" gid")||s.equals(" priority")||s.equals(" reference")||s.equals(" logto")||s.equals(" session")||s.equals(" resp")||s.equals(" react")||s.equals(" tag")||s.equals(" activates")||s.equals(" activated_by")||s.equals(" count")||s.equals(" replace")||s.equals(" detection_filter"))
			 return true;
		 return false;
		
	}
	
	public static ArrayList<RuleOption> parseRuleOption(ArrayList<String> rule_option) {
		ArrayList<RuleOption> res = new ArrayList<RuleOption>(100);
		int rule_option_size = rule_option.size();
		for(int i=0 ; i<rule_option_size; i++) {
			RuleOption ro = new RuleOption();//新建一个规则选项类
			String option = (String)rule_option.get(i);
			
			int pos = option.indexOf("content");
			String noncontent = option;
			String content = "none";
			if(pos != -1) {//存在content选项
				noncontent = option.substring(0, pos);
				content = option.substring(pos, option.length());
			}
			
			//解析noncontent
			String[] field = noncontent.split(";");
			//存储最后的警告信息
			String msg = field[0].split(":")[1];
			ro.headMap.put(" msg", msg);
			for(int j=1; j<field.length-1;j++){
				// key[j] = field[j].split(":")[0];
				// value[j]=field[j].split(":")[1];
				 if(field[j].equals(""))
					 break;
				 String k = field[j].split(":")[0];
				 if(!isIgnore(k)){
					 String val = "";
					 if(field[j].split(":").length>1)
						 val =field[j].split(":")[1];
					 ro.headMap.put(k, val);
					 //fw.write(k+":"+val+"\n");
					 //System.out.println(k+":"+val);
					 
				 }
			 }
			
			//ro.headMap存储了content字段之前的内容
			 if(content.equals("none")) {
				 res.add(ro);
				 continue;
			 }
			 
			 //进行content以及以后的内容构建
			 String[] con = content.split("content");
			 int con_len = con.length;
			 for(int j = 1; j < con_len; j++) {
				 Map<String, String> aContent = new LinkedHashMap<String, String>(50);
				 String[] block = con[j].split(";");
				 
				 int block_len = block.length;
				 for (int k = 0; k < block_len - 1; k++) {
					 String first = block[k].split(":")[0];
					 //System.out.println("the first is"+first);
					 if(!isIgnore(first)){
						 String second ="";
						 if(block[k].split(":").length>1)
							  second =block[k].split(":")[1];				 
						 //System.out.println("the second is"+second);
						 if(first.equals("")){
							 aContent.put(" content", second);
							 //fw.write("content"+":"+second);
						 }
						 else{
							 aContent.put(first,second);
							 //fw.write(first+":"+second);
						 }
					 }
				 }//对一个content内的选项进行创建
				 ro.conMap.add(aContent);
			 }//创建一个option内的所有content
			res.add(ro); 
		}//创建完所有rule头相等的选项数组
		return res;	
	}
	
	public static Rule_Header parseRuleHeader(Rule_Header rule_tmp) {
		//parse sport
		String sport = rule_tmp.sport;
		if(sport.equals("any")|| sport.contains("$")){
			rule_tmp.sport_type = 0;
		}
		
		else {
			if(sport.substring(0, 1).equals("!")) {
				rule_tmp.sport_type = -1;//是非值
				sport = sport.substring(1);
				if(!sport.contains(":")) {//是单个值
					rule_tmp.sport_val = Integer.parseInt(sport);
				}
				else{//是一个范围
					if(sport.substring(0,1).equals("["))
						sport = sport.substring(1,sport.length()-1);//将[]去除
					rule_tmp.sport_val = -1;
					String[] ports = sport.split(":");
					if(ports.length == 1){//500:
						rule_tmp.sport_low = Integer.parseInt(ports[0]);
						rule_tmp.sport_high = 65536;
					}
					else {//400:500 or :500
						if("".equals(ports[0])){//:500
							rule_tmp.sport_low = -1;
							rule_tmp.sport_high = Integer.parseInt(ports[1]);						
						}
						else {//400:500
							rule_tmp.sport_low = Integer.parseInt(ports[0]);
							rule_tmp.sport_high = Integer.parseInt(ports[1]);
						}
					
					}
				}
			}
			else {
				rule_tmp.sport_type = 1;//正值
				if(!sport.contains(":")) {//是单个值
					rule_tmp.sport_val = Integer.parseInt(sport);
				}
				else{//是一个范围
					if(sport.substring(0,1).equals("["))
						sport = sport.substring(1,sport.length()-1);//将[]去除
					rule_tmp.sport_val = -1;
					String[] ports = sport.split(":");
					if(ports.length == 1){//500:
						rule_tmp.sport_low = Integer.parseInt(ports[0]);
						rule_tmp.sport_high = 65536;
					}
					else {//400:500 or :500
						if("".equals(ports[0])){//:500
							rule_tmp.sport_low = -1;
							rule_tmp.sport_high = Integer.parseInt(ports[1]);						
						}
						else {//400:500
							rule_tmp.sport_low = Integer.parseInt(ports[0]);
							rule_tmp.sport_high = Integer.parseInt(ports[1]);
						}
					
					}
				}
				
			}
		}
		
		//parse dport
		String dport = rule_tmp.dport;
		if(dport.equals("any")|| dport.contains("$")) {
			rule_tmp.dport_type = 0;
		}
		else if(dport.equals("$HTTP_PORTS")){
			rule_tmp.dport_type = 1;
			rule_tmp.dip_val = 80;
		}
			
		else {
			if(dport.substring(0, 1).equals("!")) {
				rule_tmp.dport_type = -1;//是非值
				dport = dport.substring(1);
				if(!dport.contains(":")) {//是单个值
					rule_tmp.dport_val = Integer.parseInt(dport);
				}
				else{//是一个范围
					
					rule_tmp.dport_val = -1;
					if(dport.substring(0,1).equals("["))
						dport = dport.substring(1,dport.length()-1);//将[]去除
					String[] ports = dport.split(":");
					if(ports.length == 1){//500:
						rule_tmp.dport_low = Integer.parseInt(ports[0]);
						rule_tmp.dport_high = 65536;
					}
					else {//400:500 or :500
						if("".equals(ports[0])){//:500
							rule_tmp.dport_low = -1;
							rule_tmp.dport_high = Integer.parseInt(ports[1]);						
						}
						else {//400:500
							rule_tmp.dport_low = Integer.parseInt(ports[0]);
							rule_tmp.dport_high = Integer.parseInt(ports[1]);
						}
					
					}
				}
			}
			else {
				rule_tmp.dport_type = 1;//正值
				if(!dport.contains(":")) {//是单个值
					rule_tmp.dport_val = Integer.parseInt(dport);
				}
				else{//是一个范围
					if(dport.substring(0,1).equals("["))
						dport = dport.substring(1,dport.length()-1);//将[]去除
					rule_tmp.dport_val = -1;
					String[] ports = dport.split(":");
					if(ports.length == 1){//500:
						rule_tmp.dport_low = Integer.parseInt(ports[0]);
						rule_tmp.dport_high = 65536;
					}
					else {//400:500 or :500
						if("".equals(ports[0])){//:500
							rule_tmp.dport_low = -1;
							rule_tmp.dport_high = Integer.parseInt(ports[1]);						
						}
						else {//400:500
							rule_tmp.dport_low = Integer.parseInt(ports[0]);
							rule_tmp.dport_high = Integer.parseInt(ports[1]);
						}
					
					}
				}
				
			}
		}
		
		//parse sip
		String sip = rule_tmp.sip;
		
		if(sip.equals("$HOME_NET") ) {//内网
			rule_tmp.sip_type = -2;
		}
		else if(sip.equals("$EXTERNAL_NET")) {//外网
			rule_tmp.sip_type = 2;
		}
		else if(sip.equals("any") || sip.contains("$")) {
			rule_tmp.sip_type = 0;
		}
		else {
			if(sip.substring(0,1).equals("!")) {//非
		
				rule_tmp.sip_type = -1;
				sip = sip.substring(1);
			}
			else{//正常值
				rule_tmp.sip_type = 1;
			}
			if(sip.contains("/")) {
				int type = Integer.parseInt(sip.replaceAll(".*/", ""));
			    rule_tmp.sip_mask = 0xFFFFFFFF << (32 - type);
			    String maskIp = sip.replaceAll("/.*", "");
			    String[] maskIps = maskIp.split("\\.");
			    rule_tmp.sip_val = (Integer.parseInt(maskIps[0]) << 24)
			            | (Integer.parseInt(maskIps[1]) << 16)
			            | (Integer.parseInt(maskIps[2]) << 8)
			            | Integer.parseInt(maskIps[3]); 
			}
			else {
				rule_tmp.sip_mask = 0xFFFFFFFF;
				String[] maskIps = sip.split("\\.");
				rule_tmp.sip_val = (Integer.parseInt(maskIps[0]) << 24)
			            | (Integer.parseInt(maskIps[1]) << 16)
			            | (Integer.parseInt(maskIps[2]) << 8)
			            | Integer.parseInt(maskIps[3]);
			}
		}
		
		//parse dip
		String dip = rule_tmp.dip;
		
		if(dip.equals("$HOME_NET") ) {//内网
			rule_tmp.dip_type = -2;
		}
		else if(dip.equals("$EXTERNAL_NET")) {//外网
			rule_tmp.dip_type = 2;
		}
		else if(dip.equals("any")||dip.contains("$")) {
			rule_tmp.dip_type = 0;
		}
		
		else {
			if(dip.substring(0,1).equals("!")) {//非
		
				rule_tmp.dip_type = -1;
				dip = dip.substring(1);
			}
			else{//正常值
				rule_tmp.dip_type = 1;
			}
			if(dip.contains("/")) {
				int type = Integer.parseInt(dip.replaceAll(".*/", ""));
			    rule_tmp.dip_mask = 0xFFFFFFFF << (32 - type);
			    String maskIp = dip.replaceAll("/.*", "");
			    String[] maskIps = maskIp.split("\\.");
			    rule_tmp.dip_val = (Integer.parseInt(maskIps[0]) << 24)
			            | (Integer.parseInt(maskIps[1]) << 16)
			            | (Integer.parseInt(maskIps[2]) << 8)
			            | Integer.parseInt(maskIps[3]); 
			}
			else {
				rule_tmp.dip_mask = 0xFFFFFFFF;
				String[] maskIps = dip.split("\\.");
				rule_tmp.dip_val = (Integer.parseInt(maskIps[0]) << 24)
			            | (Integer.parseInt(maskIps[1]) << 16)
			            | (Integer.parseInt(maskIps[2]) << 8)
			            | Integer.parseInt(maskIps[3]);
			}
		}
		
		return rule_tmp;
	}
			
	public static int convertAddrStr2Int(String addr)	{
		String[] networkips = addr.split("\\.");
		int ipAddr = (Integer.parseInt(networkips[0]) << 24)
	            | (Integer.parseInt(networkips[1]) << 16)
	            | (Integer.parseInt(networkips[2]) << 8)
	            | Integer.parseInt(networkips[3]);
		return ipAddr;
	}
		

	public void cleanup() {
		// TODO Auto-generated method stub
		
	}

}
