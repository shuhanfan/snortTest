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



public class Transfer_Bolt implements IBasicBolt{

	private BasicOutputCollector outputCollector;
	public FileOutputStream out;
	public FileWriter fw ;
	private String name_bolt;
	private boolean transfer;

	public String protocol="";
	public String sip="";
	public int sport=-1;
	public String dip="";
	public int dport=-1;
	public int dsize;	
	public int ip_proto;
	public int DF;
	public int MF;
	public int Reserved;
	public long ack=-1;
	//public int start = -1;//表示应用层数据的起始偏移
	public byte[] payload;//抓取到的二进制包,从ip头起

	
	public Transfer_Bolt(){}
	public Transfer_Bolt(String nm){
		name_bolt =nm;
	}
	public void declareOutputFields(OutputFieldsDeclarer declarer) {
		// TODO Auto-generated method stub
		declarer.declare(new Fields("protocol","sip","sport","dip","dport","dsize","ip_proto","DF","MF","Reserved","ack","payload"));
	}

	public Map<String, Object> getComponentConfiguration() {
		// TODO Auto-generated method stub
		return null;
	}

	public void prepare(Map stormConf, TopologyContext context) {
		transfer = false;
		// TODO Auto-generated method stub
//		try {
//			  
//			  fw = new FileWriter("//opt//res4Snort//transferBolt");
//			//fw = new FileWriter("//Users//jessief//upload//transferBolt");
//		} catch (FileNotFoundException e) {
//			// TODO 自动生成的 catch 块
//			e.printStackTrace();
//		} catch (IOException e) {
//			// TODO 自动生成的 catch 块
//			e.printStackTrace();
//		}
		
	}

	public void execute(Tuple tuple, BasicOutputCollector collector) {
		// TODO Auto-generated method stub
		outputCollector = collector;
		//System.out.println("transferBolt0");
		outputCollector.setContext(tuple);  
		String name=tuple.getSourceComponent(); 
		//System.out.println("transferBolt1");
		try {
			if(name.equals("RuleSpout")){//当规则已经发送完毕后，才允许传输流量
				transfer =true;
				
			}
			if(name.equals("VolumeSpout")){
				if(transfer == true){
//					if(startTime == 0)
//						startTime = System.currentTimeMillis();
				//Packet_Header pcaket_tmp =new Packet_Header();
				protocol = (String)tuple.getValueByField("protocol");
				sip = (String)tuple.getValueByField("sip");
				sport=(Integer)tuple.getValueByField("sport");
				dip=(String)tuple.getValueByField("dip");
				dport=(Integer)tuple.getValueByField("dport");
				payload = (byte[]) tuple.getValueByField("payload");
				ack = (Long)tuple.getValueByField("ack");
				DF = (Integer)tuple.getValueByField("DF");
				dsize = (Integer)tuple.getValueByField("dsize");
				ip_proto = (Integer)tuple.getValueByField("ip_proto");
				Reserved= (Integer)tuple.getValueByField("Reserved");
				//**pktlen = pktlen + pcaket_tmp.payload.length;
				//System.out.println("pkheader.protocol:"+pcaket_tmp.protocol+" pcaket_tmp.sip:"+pcaket_tmp.sip+" pcaket_tmp.sport:"+pcaket_tmp.sport+" pcaket_tmp.dip:"+pcaket_tmp.dip+" pcaket_tmp.dport:"+pcaket_tmp.dport);
		           
//		    	try {
//					fw.write(pktlen+","+(System.currentTimeMillis()-startTime)+" "+((double)pktlen/(System.currentTimeMillis()-startTime))+"\n");
//					fw.flush();
//				} catch (IOException e) {
//					// TODO Auto-generated catch block
//					e.printStackTrace();
//				}
		    	
				this.outputCollector.emit(new Values(protocol,sip,sport,dip,dport,dsize,ip_proto,DF,MF,Reserved,ack,payload));
				//System.out.println("pkheader.protocol:"+pcaket_tmp.protocol+" pkheader.sip:"+pcaket_tmp.sip+" pkheader.sport:"+pcaket_tmp.sport+" pkheader.dip:"+pcaket_tmp.dip+" pkheader.dport:"+pcaket_tmp.dport);
				}
			}
		} catch(FailedException e) {
	    	System.out.println("Bolt fail to deal with packet");
	    }  

	}

	public void cleanup() {
		// TODO Auto-generated method stub
		
	}

}
