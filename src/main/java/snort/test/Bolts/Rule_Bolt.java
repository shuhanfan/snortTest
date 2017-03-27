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
//	public FileWriter fwVol ;
	
	private String name_bolt;
	private int packnum ;
	private int detect = 0;
	  //private int ruleBoltType = 0;
	
	private long pktlen = 0;//record the transport flow
	private long startTime = 0;
	private boolean transfer = false;
	
	public Rule_Bolt(String nm){
		name_bolt =nm;
	}
	public void declareOutputFields(OutputFieldsDeclarer declarer) {
		// TODO Auto-generated method stub
		declarer.declare(new Fields("packnum", "detect", "flow"));
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
		rule_set = new ArrayList<Rule_Header>(500);
//		try {
//			if(name_bolt.equals("RuleBolt1")){
//				ruleBoltType = 1;
//				fwRule = new FileWriter("//opt//res4Snort//rulespout_ruleBolt1");
//				fwVol = new FileWriter("//opt//res4Snort//volspout_ruleBolt1");
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
			if(name.equals("volume")){
				if (!transfer)
					return;				
				if(startTime == 0){
					startTime = System.currentTimeMillis();
					//fwVol.write("startTime:"+startTime);
				}			
				//System.out.println("rule bolt for vol");
				Packet_Header pcaket_tmp =new Packet_Header();
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
	//			String p = BytetoString(pcaket_tmp.payload,pcaket_tmp.payload.length);
				
				System.out.println("pkheader.protocol:"+pcaket_tmp.protocol+" pkheader.sip:"+pcaket_tmp.sip+" pkheader.sport:"+pcaket_tmp.sport+" pkheader.dip:"+pcaket_tmp.dip+" pkheader.dport:"+pcaket_tmp.dport);
				
				//对数据包进行处
				//System.out.println(" before deal with packet using rules");
				packnum++;
				//System.out.println("name:"+name_bolt+"rule_set_size:"+rule_set.size());
				int rule_size = rule_set.size();
				for(int i=0; i<rule_size; i++){
					//System.out.println("in deal packet loop");
					//System.out.println("in rule set this is"+i+" rule set size is:"+rule_set.size());
					
					if(rule_set.get(i).match(pcaket_tmp)){//选择规则选项匹配的规则进行处理
						System.out.println("the ruleset header match the packet header");
						//DealOption dp = new DealOption(rule_set.get(i),pcaket_tmp,detect);
						//detect = dp.run();
						
					}
				}
				this.outputCollector.emit(new Values(packnum, detect, pktlen));
				
				//System.out.println("pkheader.protocol:"+pcaket_tmp.protocol+" pkheader.sip:"+pcaket_tmp.sip+" pkheader.sport:"+pcaket_tmp.sport+" pkheader.dip:"+pcaket_tmp.dip+" pkheader.dport:"+pcaket_tmp.dport);
			}
			else if(name.equals("rule") )
			{				
				
				transfer = (Boolean)tuple.getValueByField("switch");
				if(transfer) {
					System.out.println("transfer==true");
					return;
				}
				System.out.println("rule bolt for rule");
				Rule_Header rule_tmp = new Rule_Header();
				rule_tmp.action=(String)tuple.getValueByField("action");
				rule_tmp.protocol=(String)tuple.getValueByField("protocol");
				rule_tmp.sip=(String)tuple.getValueByField("sip");
				rule_tmp.sport=(String)tuple.getValueByField("sport");
				rule_tmp.direction=(String)tuple.getValueByField("direction");
				rule_tmp.dip=(String)tuple.getValueByField("dip");
				rule_tmp.dport=(String)tuple.getValueByField("dport");
				rule_tmp.rule_option=(ArrayList)tuple.getValueByField("option");
				//get parsed_rule_option
				rule_tmp.parsed_rule_option = parseRuleOption(rule_tmp.rule_option);
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

	public void cleanup() {
		// TODO Auto-generated method stub
		
	}

}
