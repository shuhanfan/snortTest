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
	private int pack1, pack2, pack3, detect1, detect2, detect3;
	private long flow1, flow2,flow3;
	private long startTime;
	
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
			startTime = System.currentTimeMillis();
			pack1 = pack2 = pack3 =detect1 =detect2 = detect3 = 0;
			flow1 = flow2 =flow3 = 0;
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
				pack1 = (Integer)tuple.getValueByField("packnum");
				detect1 = (Integer)tuple.getValueByField("detect");
				flow1 = (Long)tuple.getValueByField("flow")*8;//转化成bit
			}
			else if(name.equals("RuleBolt2")){
				pack2 = (Integer)tuple.getValueByField("packnum");
				detect2 = (Integer)tuple.getValueByField("detect");
				flow2 = (Long)tuple.getValueByField("flow")*8;
			//System.out.println("pkheader.protocol:"+pcaket_tmp.protocol+" pkheader.sip:"+pcaket_tmp.sip+" pkheader.sport:"+pcaket_tmp.sport+" pkheader.dip:"+pcaket_tmp.dip+" pkheader.dport:"+pcaket_tmp.dport);
			}
			else {
				pack3 = (Integer)tuple.getValueByField("packnum");
				detect3 = (Integer)tuple.getValueByField("detect");
				flow3 = (Long)tuple.getValueByField("flow")*8;
			//System.out.println("pkheader.protocol:"+pcaket_tmp.protocol+" pkheader.sip:"+pcaket_tmp.sip+" pkheader.sport:"+pcaket_tmp.sport+" pkheader.dip:"+pcaket_tmp.dip+" pkheader.dport:"+pcaket_tmp.dport);
			}
			long total_flow = (flow1+flow2+flow3)*8;
		    long during_time = System.currentTimeMillis()-startTime;
		    if(during_time%1000==0) {
		    	double rate = (double)total_flow / during_time;
		    	fw.write("1:"+detect1+"/"+pack1+"/"+flow1+" ;2:"+detect2+"/"+pack2+"/"+flow2+" ;3:"+detect3+"/"+pack3+"/"+flow3+" ;total:"+(detect1+detect2+detect3)+"/"+(pack1+pack2+pack3)+"/"+total_flow+ " ;time: "+ during_time+" ;rate:/kbps: "+rate+"\n");
//		    	if(during_time%60000==0)
//		    		fw.flush();
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
