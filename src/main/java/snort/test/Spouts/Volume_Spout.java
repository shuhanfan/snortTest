
package snort.test.Spouts;

import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import snort.test.Helpers.CreateValue;
import snort.test.Helpers.Packet_Header;
import snort.test.Helpers.KafkaProperties;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.PcapIf;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip6;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.packet.JRegistry;

import backtype.storm.spout.SpoutOutputCollector;
import backtype.storm.task.TopologyContext;
import backtype.storm.topology.IRichSpout;
import backtype.storm.topology.OutputFieldsDeclarer;
import backtype.storm.tuple.Fields;
import backtype.storm.tuple.Values;

import java.util.Properties;
//
//import kafka.consumer.ConsumerConfig;
//import kafka.consumer.ConsumerIterator;
//import kafka.consumer.KafkaStream;
//import kafka.javaapi.consumer.ConsumerConnector;

public class Volume_Spout implements Serializable,IRichSpout  {

	private SpoutOutputCollector outputCollector;
	PcapIf device;
	Pcap pcap; 
	boolean linux = true;
	int hsize = 0;
	StringBuilder errbuf = new StringBuilder(); // For any error msgs
	//vars
	private PcapPacket packet = null;  
	//private Tcp tcp = null;
	//private Udp udp = null;
	//private Http http = null;
	//private CreateValue create;
	//public FileWriter fw ;
	
	//start capture
	private String deviceName = null;
	private int count = -1;
	private String filter = null;
	private String srcFilename =null ;
	private String dstFilename = null;
	private int sampLen = 64*1024;
	public int countPacket = 0;
	private int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
	private int timeout = 10 ; // 10 seconds in millis
	private long pktlen = 0;//record the transport flow
	private long startTime = 0;
	
	//public FileWriter fw;
	
	
//	private ConsumerConnector consumer;
	
    private String topic=null;
//    private Map<String, Integer> topicCountMap;
//    private Map<String, List<KafkaStream<byte[], byte[]>>> consumerMap;
//    private KafkaStream<byte[], byte[]> stream;
//    private ConsumerIterator<byte[], byte[]> it;
//    
//    
//    private static ConsumerConfig createConsumerConfig()
//    {
//        Properties props = new Properties();
//        props.put("zookeeper.connect", KafkaProperties.zkServer);
//        props.put("group.id", "group1");
//        props.put("zookeeper.session.timeout.ms", "40000");
//        props.put("zookeeper.sync.time.ms", "200");
//        props.put("auto.commit.interval.ms", "1000");
//        return new ConsumerConfig(props);
//    }
	
		
	//test
	//public Ip4 ip4;
	//public Ip6 ip6;
	public String src=null;
	public String dst=null;
	int id;
	//int aamount = 0;
	long time = 0;
	long slots = 0;
	long throughput = 0;
	 //PcapPacket packet;
	// long countPacket = 0;
	 //PcapHeader hdr;  
     	//JBuffer buf; 
	//PcapPacket packet;
	
	//for kafka
	
    public Volume_Spout(){};
   
    
    public Volume_Spout(String deviceName, int count, String filter, String srcFilename, String dstFilename, int sampLen,String topic){
    	this.deviceName = "eth0";
    	this.count = count; 
    	this.filter = filter;
    	this.srcFilename = srcFilename;
    	this.dstFilename = dstFilename;
    	if(sampLen<0)
    		this.sampLen = 64*1024;
    	this.sampLen = sampLen;
//    	 try {
// 			  fw = new FileWriter("//opt//res4Snort//volumeSpout",true);
// 		} catch (FileNotFoundException e) {
// 			// TODO 自动生成的 catch 块
// 			e.printStackTrace();
// 		} catch (IOException e) {
// 			// TODO 自动生成的 catch 块
// 			e.printStackTrace();
// 		}
    	
    	this.topic=topic;
    

    }
    public Volume_Spout(String deviceName, String count, String filter, String srcFilename, String dstFilename, String sampLen,String topic){
    	this.deviceName = "eth0";
    	this.count = Integer.parseInt(count); //閺堫亙濞囬悽顭掔礉閺冪姵鏅�
    	this.filter = filter;
    	this.srcFilename = srcFilename;
    	this.dstFilename = dstFilename;
    	int slen=0;
    	if(Integer.parseInt(sampLen)<0)
            slen = 64*1024;// Capture all packets, no trucation
    	this.sampLen = slen;
//    	try {
//			  fw = new FileWriter("//opt//res4Snort//volumeSpout",true);
//		} catch (FileNotFoundException e) {
//			// TODO 自动生成的 catch 块
//			e.printStackTrace();
//		} catch (IOException e) {
//			// TODO 自动生成的 catch 块
//			e.printStackTrace();
//		}
   	
    	this.topic=topic;
    

    }
    
    PcapIf getDevice(){
    	List<PcapIf> alldevs = new ArrayList<PcapIf>(); // Will be filled with NICs
    	int r = Pcap.findAllDevs(alldevs, errbuf);
		if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
			System.err.printf("Can't read list of devices, error is %s", errbuf.toString());
			return null;
		}
		int i = 0,chooseid=8;
		for (PcapIf device : alldevs) {
			//System.out.println(i+"device is "+device.getName()+" and "+device.getName().equals("eth0"));
			String description =(device.getDescription() != null) ? device.getDescription(): "No description available";
			if(device.getName().equals("eth0")||device.getName().equals("em1"))//245或者200的内网卡
				chooseid=i;
			i++;
			System.out.printf("#%d: %s [%s]\n", i, device.getName(), description);
		}
		System.out.println("bbbbbbbbbbbbbbbbbbthe final device num is:"+chooseid);
		/*try {
			fw.write("final device num is:"+chooseid);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}*/
		
		return alldevs.get(chooseid);
    }
	
	public void open(Map arg0, TopologyContext arg1, SpoutOutputCollector spoutOutputCollector) {
		// TODO Auto-generated method stub
		this.outputCollector = spoutOutputCollector;		
        try { 
        //从kafka队列获取专用：流量（根据topic以及consumer config的内容）
//        	this.consumer = kafka.consumer.Consumer.createJavaConsumerConnector(
//                    createConsumerConfig());
//        	this.topicCountMap = new HashMap<String, Integer>();
//            topicCountMap.put(topic, new Integer(1));
//            this.consumerMap = consumer.createMessageStreams(topicCountMap);
//            this.stream = consumerMap.get(topic).get(0);
//            this.it = stream.iterator();
        
            
           
  		
        	//open device
            
        	if(srcFilename!=null){
        		//System.out.println("come to the srcFile is not null");
        	//	fw.write("open offline srcFile\n");
        		//pcap=Pcap.openOffline(srcFilename, errbuf);
        		pcap=Pcap.openOffline("//opt//res4Snort//inside.pcap", errbuf);
        		//System.out.println("after open~~~~~~~~~~~~~~");
        	
        		
        		if (pcap == null) {
        			System.err.printf("Error while opening srcfile  for capture: "+ errbuf.toString());
        			return;
        		}
			id = JRegistry.mapDLTToId(pcap.datalink());
			 //hdr = new PcapHeader(JMemory.POINTER);  
			 //buf = new JBuffer(JMemory.POINTER);
			 packet=new PcapPacket(JMemory.POINTER);
			 startTime = System.currentTimeMillis();
        	}
        	else
        	{
        		//System.out.println("come to the srcFile is null");
        		this.sampLen=64*1024;
        		//System.out.println("before getDevice");
        		device = getDevice();
        		//System.out.println("after getDevice");
        		//System.out.println(device);
        		//System.out.println(this.sampLen);
        		
        		pcap =Pcap.openLive(device.getName(), this.sampLen, this.flags, this.timeout, errbuf);
        	
        		//pcap=Pcap.openOffline("/opt/topology/pcap/temp3.pcap", errbuf);
        		if (pcap == null) {
        			System.err.printf("Error while opening device for capture: "+ errbuf.toString());
        			return;
        		}
        	startTime = System.currentTimeMillis();
			id = JRegistry.mapDLTToId(pcap.datalink());
			 //hdr = new PcapHeader(JMemory.POINTER);  
			 //buf = new JBuffer(JMemory.POINTER);
			packet=new PcapPacket(JMemory.POINTER);
			//create= new CreateValue();
        	}//device获取专用
        	
        	//ip4=new Ip4();	
        	//ip6=new Ip6();
        	//apply space
        	//hdr = new PcapHeader();  
           // buf = new JBuffer(JMemory.POINTER);
            //this.packet =new PcapPacket(hdr,buf); 
        	
        	
        } catch (Exception e) {
            e.printStackTrace();
        }
	}
	
	public void nextTuple() {
		//int flag=0;
		// TODO Auto-generated method stub
		//System.out.println("This is before nextTuple try");
		try{
			//kafka队列获取专用if(this.it.hasNext())
			//device获取用if(pcap.nextEx(packet)==1)
		    if(pcap.nextEx(packet)==1)
			{
				CreateValue cv = new CreateValue(packet);
//				System.out.println("after packet_header");
//		    	System.out.println(cv.protocol);
//		    	System.out.println(cv.sip);
//		    	System.out.println(cv.sport);
//		    	System.out.println(cv.dip);
//		    	System.out.println(cv.dport);
//		    	System.out.println(cv.ack);
//		    	System.out.println(cv.DF);
//		    	System.out.println(cv.MF);
//		    	System.out.println(cv.Reserved);
//		    	System.out.println(cv.payload_size);
//		    	System.out.println(cv.payload_offset_from_network); 
//		    	System.out.println(cv.ip_proto); 
		    	//aamount++;
		    	//System.out.println("the amount is:"+aamount);
		    	//fw.write("the amount is:"+aamount+"\n");
		    	//fw.flush();
				//countPacket++;
				//System.out.println("next tuple");
				//SystFem.out.println("if(this.it.hasNext())");
				
				//kafka队列获取专用，得到二进制流量
//				 byte[] dstpacket=it.next().message();
//				 packet = new PcapPacket(dstpacket);
				 
				/*
				 * 
				for (int k = 0; k < dstpacket.length; k++) {
					String hex = Integer.toHexString(dstpacket[k] & 0xFF);
					if (hex.length() == 1) {
						hex = '0' + hex;
					}
					fw.write(hex.toUpperCase() + " ");
				}
				fw.write("\n");
				*/
			/*	
				if(linux == true)
					hsize = 8;
				else
					hsize = 0;
				
				//System.out.println("sending packet");
				
				byte[] babuf = new byte[packet.getTotalSize()];
				byte[] pcapbuf = new byte[packet.getTotalSize()-packet.getState().size()-hsize];
				packet.transferStateAndDataTo(babuf);
			
				
				//System.out.println("packet.getCaptureHeader().size():"+packet.getCaptureHeader().size());
						
        		if(linux==false){
        			for(int i=0;i<16;i++){
						pcapbuf[i]=babuf[i];
					}
        			for(int k=0;k<packet.getTotalSize()-packet.getState().size()-16;k++){
                    	pcapbuf[16+k]=babuf[packet.getState().size()+16+k];
                    	}
        			//System.out.println("here1");
        		}	
        		
        		else{
                    pcapbuf[0]=babuf[0];       //秒
                    pcapbuf[1]=babuf[1];
                    pcapbuf[2]=babuf[2];
                    pcapbuf[3]=babuf[3];
                    
                    pcapbuf[4]=babuf[8];      //微秒
                    pcapbuf[5]=babuf[9];
                    pcapbuf[6]=babuf[10];
                    pcapbuf[7]=babuf[11];
                    
                    pcapbuf[8]=babuf[16];     //采集长度
                    pcapbuf[9]=babuf[17];
                    pcapbuf[10]=babuf[18];
                    pcapbuf[11]=babuf[19];
                    
                    pcapbuf[12]=babuf[20];    //实际长度
                    pcapbuf[13]=babuf[21];
                    pcapbuf[14]=babuf[22];
                    pcapbuf[15]=babuf[23];
                    
                   
                   ///if(packet.getState().size())
                    for(int k=0;k<packet.getTotalSize()-packet.getState().size()-24;k++){
                    	pcapbuf[16+k]=babuf[packet.getState().size()+24+k];
                    	}
        		}
        		*/
        		//pcapbuf是最正常的pcap包格式 16字节pcap头+数据包
        		
        		//处理之前，测试接收到的流量
        		//pktlen = pktlen + cv.network_size+114;
        		//long during_time = System.currentTimeMillis()-startTime;
        		//**System.out.println(pktlen+","+ during_time +","+((double)pktlen/during_time));
        		
        		
        		
		    	//Packet_Header pkheader = new Packet_Header(pcapbuf);
		    	
		    	
				//System.out.println("dstpacket.toString():"+new String(dstpacket));
				//System.out.println("byte[] dstpacket=it.next().message();");
				//System.out.println("dstpacket.length:"+dstpacket.length);
				//PcapPacket p1 = new PcapPacket(JMemory.POINTER);
				//p1.transferStateAndDataFrom(dstpacket);
				//PcapPacket p1 = new PcapPacket(dstpacket);
		    
		    		
		    	
				
				//device获取用
				//System.out.println("get flow form the device,the spout payload is:"+babuf);
				
				
				/*byte[] pkbuf = new byte[packet.getTotalSize()-packet.getState().size()-16];
	            packet.transferStateAndDataTo(babuf);
	            
	            
	            for (int k = 0; k < babuf.length-packet.getState().size()-16; k++) {
	            	pkbuf[k] = babuf[k+packet.getState().size()+16];
				}*/
	            
	            	
	            	/*
	            	if(pkheader.protocol.equals("icmp")){
	            	System.out.println("pkheader.protocol:"+pkheader.protocol+" pkheader.sip:"+pkheader.sip+" pkheader.sport:"+pkheader.sport+" pkheader.dip:"+pkheader.dip+" pkheader.dport:"+pkheader.dport);
	            	}
	            	*/
		    	//fw.write(cbuf);
		    	
		    	//处理之后测试流量发送速率
	           
//		    	pktlen = pktlen + pkheader.payload.length;
//        		long during_time = System.currentTimeMillis()-startTime;
//        		System.out.println(pktlen+","+ during_time +","+((double)pktlen/during_time));
//		        this.outputCollector.emit("volume",new Values(pkheader.protocol,pkheader.sip,pkheader.sport,pkheader.dip,pkheader.dport,pkheader.dsize,pkheader.ip_proto,pkheader.DF,pkheader.MF,pkheader.Reserved,pkheader.ack,pkheader.start,pcapbuf));
//        		
        		this.outputCollector.emit("volume",new Values(cv.protocol,cv.sip,cv.sport,cv.dip,cv.dport,cv.dsize,cv.ip_proto,cv.DF,cv.MF,cv.Reserved,cv.fragoffset,cv.ttl,cv.tos,cv.id,cv.flags,cv.seq,cv.ack,cv.window,cv.sameip,cv.payload));
				///***///
        		System.out.println("protocol:"+cv.protocol+",sip:"+cv.sip+",sport:"+cv.sport+",dip:"+cv.dip+",dport:"+cv.dport+",dsize:"+cv.dsize+",ip_proto:"+cv.ip_proto+",DF:"+cv.DF+",MF:"+cv.MF+",Reserved:"+cv.Reserved+",cv.fragoffset:"+cv.fragoffset+",cv.ttl:"+cv.ttl+",cv.tos:"+cv.tos+",cv.id:"+cv.id+",cv.flags"+cv.flags+",cv.seq:"+cv.seq+",cv.ack:"+cv.ack+",cv.window:"+cv.window+",cv.sameip:"+cv.sameip);

	           
				//System.out.println("this.outputCollector.emit(basic,new Values(p1.getCaptureHeader().seconds(), null , null,p1.getCaptureHeader().caplen()));");
			}    
		} catch(Exception e) {
			    	System.out.println("in volumeSpout"+" fail to deal with packet:"+e.getMessage());
			    }
			    //this.outputCollector.emit("basic",create.createValues(packet));
			

		//System.out.println("This is after nextTuple try");
	}
	
	public void declareOutputFields(OutputFieldsDeclarer outputFieldsDeclarer) {
		// TODO Auto-generated method stub
		//outputFieldsDeclarer.declare(new Pcap().createFields());
//		outputFieldsDeclarer.declareStream("basic",new Fields("sec","src","dst","len"));//后面bolt都依据这个方法来定义字段
//		outputFieldsDeclarer.declareStream("udp",new Fields("sec","src","dst","len","src_port","dst_port"));
//		outputFieldsDeclarer.declareStream("tcp",new Fields("sec","src","dst","len","src_port","dst_port"));
		outputFieldsDeclarer.declareStream("volume",new Fields("protocol","sip","sport","dip","dport","dsize","ip_proto","DF","MF","Reserved","fragoffset","ttl","tos","id","flags","seq","ack","window","sameip","payload"));
		//outputFieldsDeclarer.declareStream("volume",new Fields("protocol","sip","sport","dip","dport"));
		//outputFieldsDeclarer.declareStream("ip",new Fields("sec","src","dst","len"));
		//outputFieldsDeclarer.declareStream("http",new Fields());
		//outputFieldsDeclarer.declareStream("volume",new Fields("basic"));
		//outputFieldsDeclarer.declareStream("volume",new Fields("payload"));
		
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
    		//pcap.close();
    	}

    	public void deactivate() {
    		// TODO Auto-generated method stub
    		
    	}

    	public void fail(Object arg0) {
    		// TODO Auto-generated method stub
    		
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
