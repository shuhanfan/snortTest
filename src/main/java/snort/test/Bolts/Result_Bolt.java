package snort.test.Bolts;

import java.util.ArrayList;
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



public class Result_Bolt implements IBasicBolt{

	private BasicOutputCollector outputCollector;
	//private ArrayList<Rule_Header> rule_set;
	public FileOutputStream out;
	public FileWriter fw ;
	private String name_bolt;
	private int rpack1, rpack2, rpack3, ppack1, ppack2, ppack3, detect1, detect2, detect3;
	private long rflow1, rflow2,rflow3, pflow1, pflow2, pflow3;
	private long lastTime;
	private long curTime;
	
	public Result_Bolt(){}
	public Result_Bolt(String nm){
		name_bolt =nm;
	}
	public void declareOutputFields(OutputFieldsDeclarer declarer) {
		// TODO Auto-generated method stub
		declarer.declare(new Fields("timestamp","throughput","countPacket"));
	}

	public Map<String, Object> getComponentConfiguration() {
		// TODO Auto-generated method stub
		return null;
	}

	public void prepare(Map stormConf, TopologyContext context) {
		//////////////
		try {
			fw = new FileWriter("//opt//res4Snort//Result");
			lastTime = System.currentTimeMillis();
			rpack1 = rpack2 = rpack3 = ppack1 = ppack2 = ppack3 =detect1 =detect2 = detect3 = 0;
			rflow1 = rflow2 = rflow3 = pflow1 = pflow2 = pflow3 = 0;
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		//////////////
		//rule_set = new ArrayList<Rule_Header>();
		// TODO Auto-generated method stub
		
	}

	public void execute(Tuple tuple, BasicOutputCollector collector) {
		// TODO Auto-generated method stub
		outputCollector = collector;
		outputCollector.setContext(tuple);  
		String name=tuple.getSourceComponent();  	
		//////////////
		try {
			if(name.equals("RuleBolt1")){
				rpack1 = (Integer)tuple.getValueByField("packnum");
				rflow1 = (Long)tuple.getValueByField("flow")*8;//转化成bit
			}
			else if(name.equals("RuleBolt2")){
				rpack2 = (Integer)tuple.getValueByField("packnum");
				rflow2 = (Long)tuple.getValueByField("flow")*8;
			////System.out.println("pkheader.protocol:"+pcaket_tmp.protocol+" pkheader.sip:"+pcaket_tmp.sip+" pkheader.sport:"+pcaket_tmp.sport+" pkheader.dip:"+pcaket_tmp.dip+" pkheader.dport:"+pcaket_tmp.dport);
			}
			else if(name.equals("RuleBolt3")){
				rpack3 = (Integer)tuple.getValueByField("packnum");
				rflow3 = (Long)tuple.getValueByField("flow")*8;
			////System.out.println("pkheader.protocol:"+pcaket_tmp.protocol+" pkheader.sip:"+pcaket_tmp.sip+" pkheader.sport:"+pcaket_tmp.sport+" pkheader.dip:"+pcaket_tmp.dip+" pkheader.dport:"+pcaket_tmp.dport);
			}
			else if(name.equals("PayloadBolt1")){
				ppack1 = (Integer)tuple.getValueByField("packnum");
				detect1 = (Integer)tuple.getValueByField("detect");
				//System.out.println("the received detect1 is:"+detect1);
				pflow1 = (Long)tuple.getValueByField("flow")*8;//转化成bit
			}
			else if(name.equals("PayloadBolt2")){
				ppack2 = (Integer)tuple.getValueByField("packnum");
				detect2 = (Integer)tuple.getValueByField("detect");
				//System.out.println("the received detect2 is:"+detect2);
				pflow2 = (Long)tuple.getValueByField("flow")*8;
			////System.out.println("pkheader.protocol:"+pcaket_tmp.protocol+" pkheader.sip:"+pcaket_tmp.sip+" pkheader.sport:"+pcaket_tmp.sport+" pkheader.dip:"+pcaket_tmp.dip+" pkheader.dport:"+pcaket_tmp.dport);
			}
			else if(name.equals("PayloadBolt3")){
				ppack3 = (Integer)tuple.getValueByField("packnum");
				detect3 = (Integer)tuple.getValueByField("detect");
				//System.out.println("the received detect3 is:"+detect3);
				pflow3 = (Long)tuple.getValueByField("flow")*8;
			////System.out.println("pkheader.protocol:"+pcaket_tmp.protocol+" pkheader.sip:"+pcaket_tmp.sip+" pkheader.sport:"+pcaket_tmp.sport+" pkheader.dip:"+pcaket_tmp.dip+" pkheader.dport:"+pcaket_tmp.dport);
			}
			long total_flow = (rflow1+ rflow2+ rflow3 + pflow1 + pflow2 + pflow3);
			curTime = System.currentTimeMillis();
		    long during_time = curTime-lastTime;
		    if(during_time/1000>0) {
		    	double rate = (double)total_flow / during_time;
		    	fw.write("1:"+ rpack1+"/"+ rflow1+" ;2:"+rpack2+"/"+rflow2+" ;3:"+rpack3+"/"+rflow3+"4:"+detect1+"/"+ ppack1+"/"+ pflow1+" ;5:"+detect2+"/"+ppack2+"/"+pflow2+" ;6:"+detect3+"/"+ppack3+"/"+pflow3+" ;total:"+(detect1+detect2+detect3)+"/"+(rpack1+rpack2+rpack3+ppack1+ppack2+ppack3)+"/"+total_flow+ " ;time: "+ during_time+" ;rate:/kbps: "+rate+"\n");
//		    	if(during_time%60000==0)
//		    		fw.flush();
		    	lastTime = curTime;
		    }
		} catch(FailedException e) {
	    	System.out.println("Bolt fail to deal with packet");
	    } catch(IOException e){
	    	
	    	e.printStackTrace();
	    }
		///////////////

	}

	public void cleanup() {
		// TODO Auto-generated method stub
		
	}

}
